import sbt.Keys.scalaVersion

name := "jwt"

organization := "io.igl"

version := "1.2.2"

scalaVersion := "2.12.3"
crossScalaVersions := Seq("2.11.11", "2.12.3")

libraryDependencies ++= Seq(
  "com.typesafe.play" %% "play-json" % "2.6.3",
  "commons-codec" % "commons-codec" % "1.10",
  "org.scalatest" %% "scalatest" % "3.0.1" % Test
)

publishMavenStyle := true

publishArtifact in Test := false

publishTo := {
  val nexus = "https://oss.sonatype.org/"
  if (isSnapshot.value)
    Some("snapshots" at nexus + "content/repositories/snapshots")
  else
    Some("releases"  at nexus + "service/local/staging/deploy/maven2")
}

pomExtra := (
  <url>github.com/iain-logan/jwt</url>
  <licenses>
    <license>
      <name>MIT License</name>
      <url>http://www.opensource.org/licenses/mit-license.php</url>
      <distribution>repo</distribution>
    </license>
  </licenses>
  <scm>
    <url>git@github.com:iain-logan/jwt.git</url>
    <connection>scm:git:git@github.com:iain-logan/jwt.git</connection>
  </scm>
  <developers>
    <developer>
      <id>iain-logan</id>
      <name>Iain Logan</name>
      <url>igl.io</url>
    </developer>
  </developers>)
