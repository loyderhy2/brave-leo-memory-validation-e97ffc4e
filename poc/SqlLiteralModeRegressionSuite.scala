/*
 * Local-only PostgreSQL semantics test for Netflix/atlas commit
 * be85494f3f4b910f91890b69bf47f0ee25662829.
 */
package com.netflix.atlas.postgres

import com.netflix.atlas.core.index.TagQuery
import com.netflix.atlas.core.model.Query
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres
import munit.FunSuite

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import java.sql.Connection
import java.sql.DriverManager
import java.time.Instant
import scala.util.Using

class SqlLiteralModeRegressionSuite extends FunSuite {

  private var postgres: EmbeddedPostgres = _
  private var connection: Connection = _

  override def beforeAll(): Unit = {
    postgres = EmbeddedPostgres
      .builder()
      .setCleanDataDirectory(true)
      .setPort(54322)
      .start()

    Class.forName("org.postgresql.Driver")
    connection = DriverManager.getConnection(
      "jdbc:postgresql://localhost:54322/postgres",
      "postgres",
      "postgres"
    )
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

  test("escapeLiteral mode changes a backslash tag value under the PostgreSQL default") {
    execute("create extension if not exists hstore")
    execute(SqlUtils.createSchema)

    val time = Instant.ofEpochMilli(1647892800000L)
    val table = TableDefinition("*", "literal_probe", Nil, "varchar(255)")
    val tableName = s"atlas.literal_probe_${SqlUtils.toSuffix(time)}"
    execute(s"drop table if exists $tableName")
    execute(SqlUtils.createTable(table, time))

    val oneBackslash = "tenant\\prod"
    val twoBackslashes = "tenant\\\\prod"

    Using.resource(
      connection.prepareStatement(
        s"insert into $tableName(values, tags) values (?::float8[], hstore(array['scope','marker'], array[?,?]))"
      )
    ) { ps =>
      ps.setString(1, "{1.0}")
      ps.setString(2, oneBackslash)
      ps.setString(3, "single")
      assertEquals(ps.executeUpdate(), 1)

      ps.setString(1, "{2.0}")
      ps.setString(2, twoBackslashes)
      ps.setString(3, "double")
      assertEquals(ps.executeUpdate(), 1)
    }

    val mode = scalar("show standard_conforming_strings")
    assertEquals(mode, "on")

    val tq = TagQuery(Some(Query.Equal("scope", oneBackslash)), Some("marker"))
    val generatedSql = SqlUtils.valueQueries(time, List(table), tq).head
    val generatedResult = scalar(generatedSql)

    val boundResult = Using.resource(
      connection.prepareStatement(s"select tags -> 'marker' from $tableName where tags -> 'scope' = ?")
    ) { ps =>
      ps.setString(1, oneBackslash)
      Using.resource(ps.executeQuery()) { rs =>
        assert(rs.next())
        val v = rs.getString(1)
        assert(!rs.next())
        v
      }
    }

    // The current SQL builder queries the row containing two backslashes,
    // whereas a parameterized exact comparison queries the intended one-backslash row.
    assertEquals(generatedResult, "double")
    assertEquals(boundResult, "single")

    val output = sys.env.getOrElse("ATLAS_LITERAL_RESULT", "atlas-sql-literal-mode-result.json")
    val atlasCommit = sys.env.getOrElse("ATLAS_COMMIT", "unknown")
    val result =
      s"""{
         |  "verdict": "PASS",
         |  "atlas_commit": ${jsonQuote(atlasCommit)},
         |  "postgresql_standard_conforming_strings": ${jsonQuote(mode)},
         |  "input_value": ${jsonQuote(oneBackslash)},
         |  "control_second_row_value": ${jsonQuote(twoBackslashes)},
         |  "escape_literal_output": ${jsonQuote(SqlUtils.escapeLiteral(oneBackslash))},
         |  "generated_sql": ${jsonQuote(generatedSql)},
         |  "generated_query_result": ${jsonQuote(generatedResult)},
         |  "parameterized_control_result": ${jsonQuote(boundResult)},
         |  "demonstrated_effect": "current generated SQL compares against two backslashes instead of the attacker-supplied one-backslash semantic atom"
         |}
         |""".stripMargin

    Files.writeString(Paths.get(output), result, StandardCharsets.UTF_8)
    println("ATLAS_SQL_LITERAL_MODE_POC=PASS")
    println(result)
  }
}
