package io.igl.jwt

trait Field {
  val name: String
}

trait JwtField extends Field