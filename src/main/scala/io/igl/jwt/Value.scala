package io.igl.jwt

import play.api.libs.json._

trait Value {
  val field: Field
  val value: Any
  val jsValue: JsValue
  val jsPair: (String, JsValue)
}

abstract class JwtValue extends Value {
  lazy val jsPair = field.name -> jsValue
}