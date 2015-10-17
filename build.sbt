name := "jwt"

organization := "io.igl"

version := "1.1.0"

scalaVersion := "2.11.7"

libraryDependencies ++= Seq(
  "com.typesafe.play" %% "play-json" % "2.4.0",
  "commons-codec" % "commons-codec" % "1.10",
  "org.scalatest" % "scalatest_2.11" % "2.2.4" % "test"
)

publishTo := Some(Resolver.file("file", new File(Path.userHome.absolutePath+"/.m2/jwt")))
