/*
 * Local-only malformed-Unicode handling test for Netflix/atlas commit
 * be85494f3f4b910f91890b69bf47f0ee25662829.
 */
package com.netflix.atlas.postgres

import com.netflix.atlas.core.util.SortedTagMap
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres
import munit.FunSuite
import org.postgresql.copy.CopyManager
import org.postgresql.core.BaseConnection

import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import java.sql.Connection
import java.sql.DriverManager
import scala.util.Using

class BinaryCopyBufferUnicodeRegressionSuite extends FunSuite {

  private var postgres: EmbeddedPostgres = _
  private var connection: Connection = _
  private var copyManager: CopyManager = _

  override def beforeAll(): Unit = {
    postgres = EmbeddedPostgres
      .builder()
      .setCleanDataDirectory(true)
      .setPort(54323)
      .start()

    Class.forName("org.postgresql.Driver")
    connection = DriverManager.getConnection(
      "jdbc:postgresql://localhost:54323/postgres",
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

  private def scalar(sql: String): String = {
    Using.resource(connection.createStatement()) { stmt =>
      Using.resource(stmt.executeQuery(sql)) { rs =>
        assert(rs.next())
        val v = rs.getString(1)
        assert(!rs.next())
        v
      }
    }
  }

  private def jsonQuote(s: String): String = {
    val b = new java.lang.StringBuilder(s.length + 16)
    b.append('"')
    var i = 0
    while (i < s.length) {
      val c = s.charAt(i)
      c match {
        case '"'  => b.append("\\\"")
        case '\\' => b.append("\\\\")
        case '\n' => b.append("\\n")
        case '\r' => b.append("\\r")
        case '\t' => b.append("\\t")
        case _ if Character.isSurrogate(c) => b.append(f"\\u${c.toInt}%04x")
        case _ if c < ' '                  => b.append(f"\\u${c.toInt}%04x")
        case _                             => b.append(c)
      }
      i += 1
    }
    b.append('"').toString
  }

  test("BinaryCopyBuffer must not silently truncate malformed Unicode") {
    execute("create extension if not exists hstore")
    execute("drop table if exists atlas_binary_unicode_text")
    execute("drop table if exists atlas_binary_unicode_hstore")
    execute("create table atlas_binary_unicode_text(value text)")
    execute("create table atlas_binary_unicode_hstore(value hstore)")

    val malformed = "admin" + 0xD800.toChar + "-not-admin"
    assert(malformed != "admin")

    val strictEncoderResult = StandardCharsets.UTF_8
      .newEncoder()
      .encode(CharBuffer.wrap(malformed), java.nio.ByteBuffer.allocate(1024), true)
    assert(strictEncoderResult.isMalformed)

    val textBuffer = new BinaryCopyBuffer(4096, 1)
    assert(textBuffer.putString(malformed).nextRow())
    textBuffer.copyIn(copyManager, "atlas_binary_unicode_text")

    val hstoreBuffer = new BinaryCopyBuffer(4096, 1)
    assert(hstoreBuffer.putTagsHstore(SortedTagMap("role" -> malformed)).nextRow())
    hstoreBuffer.copyIn(copyManager, "atlas_binary_unicode_hstore")

    val storedText = scalar("select value from atlas_binary_unicode_text")
    val storedRole = scalar("select value -> 'role' from atlas_binary_unicode_hstore")

    // encodeString checks only OVERFLOW. A MALFORMED result is ignored, so only
    // the valid prefix is persisted and the suffix beginning at the surrogate is lost.
    assertEquals(storedText, "admin")
    assertEquals(storedRole, "admin")

    val output = sys.env.getOrElse(
      "ATLAS_UNICODE_RESULT",
      "atlas-binary-unicode-result.json"
    )
    val atlasCommit = sys.env.getOrElse("ATLAS_COMMIT", "unknown")
    val result =
      s"""{
         |  "verdict": "PASS",
         |  "atlas_commit": ${jsonQuote(atlasCommit)},
         |  "attacker_input": ${jsonQuote(malformed)},
         |  "input_equals_admin": false,
         |  "strict_utf8_encoder_result": ${jsonQuote(strictEncoderResult.toString)},
         |  "stored_text": ${jsonQuote(storedText)},
         |  "stored_hstore_role": ${jsonQuote(storedRole)},
         |  "demonstrated_effect": "an input that is not admin is silently persisted as admin because MALFORMED CharsetEncoder results are ignored"
         |}
         |""".stripMargin

    Files.writeString(Paths.get(output), result, StandardCharsets.UTF_8)
    println("ATLAS_BINARY_UNICODE_POC=PASS")
    println(result)
  }
}
