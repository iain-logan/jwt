package io.igl.jwt

import play.api.libs.json.{JsString, JsValue}

trait HeaderValue extends JwtValue

trait HeaderField extends JwtField {
  def attemptApply(value: JsValue): Option[HeaderValue]
}

case class Typ(value: String) extends HeaderValue {
  override val field: Field = Typ
  override val jsValue: JsValue = JsString(value)
}

object Typ extends HeaderField {
  override def attemptApply(value: JsValue): Option[Typ] =
    value.asOpt[String].map(apply)

  override val name: String = "typ"
}

case class Alg(value: Algorithm) extends HeaderValue {
  override val field = Alg
  override val jsValue: JsValue = JsString(value.name)
}

object Alg extends HeaderField {
  override def attemptApply(value: JsValue): Option[Alg] =
    value.asOpt[String].flatMap(Algorithm.getAlgorithm).map(apply)

  override val name = "alg"
}

object Cty extends HeaderValue with HeaderField {
  override def attemptApply(value: JsValue): Option[HeaderValue] =
    value.asOpt[String].map{case this.value => Cty}

  override val name: String = "cty"
  override val field: Field = this
  override val value: String = "JWT"
  override val jsValue: JsValue = JsString(value)
}