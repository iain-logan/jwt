package io.igl.jwt

import play.api.libs.json.{JsNumber, JsArray, JsString, JsValue}

trait ClaimValue extends JwtValue

trait ClaimField extends JwtField {
  def attemptApply(value: JsValue): Option[ClaimValue]
}

case class Iss(value: String) extends ClaimValue {
  override val field: Field = Iss
  override val jsValue: JsValue = JsString(value)
}

object Iss extends ClaimField {
  override def attemptApply(value: JsValue): Option[ClaimValue] =
    value.asOpt[String].map(apply)

  override val name: String = "iss"
}

case class Sub(value: String) extends ClaimValue {
  override val jsValue = JsString(value)
  override val field: Field = Sub
}

object Sub extends ClaimField {
  override def attemptApply(value: JsValue): Option[Sub] =
    value.asOpt[String].map(apply)

  override val name: String = "sub"
}

case class Aud(value: Either[String, Seq[String]]) extends ClaimValue {
  override val field: Field = Aud
  override val jsValue: JsValue = value match {
    case Left(single) => JsString(single)
    case Right(many) => JsArray(many.map(JsString))
  }
}

object Aud extends ClaimField {
  override def attemptApply(value: JsValue): Option[ClaimValue] =
    value.asOpt[Seq[String]].map(v => Aud(Right(v))).orElse{
      value.asOpt[String].map(v => Aud(Left(v)))
    }

  override val name: String = "aud"
}

case class Exp(value: Long) extends ClaimValue {
  override val field: Field = Cty
  override val jsValue: JsValue = JsNumber(value)
}

case object Exp extends ClaimField {
  override def attemptApply(value: JsValue): Option[ClaimValue] =
    value.asOpt[Long].map(apply)

  override val name: String = "exp"
}

case class Nbf(value: Long) extends ClaimValue {
  override val field: Field = Nbf
  override val jsValue: JsValue = JsNumber(value)
}

object Nbf extends ClaimField {
  override def attemptApply(value: JsValue): Option[ClaimValue] =
    value.asOpt[Long].map(apply)

  override val name: String = "nbf"
}

case class Iat(value: Long) extends ClaimValue {
  override val field: Field = Nbf
  override val jsValue: JsValue = JsNumber(value)
}

object Iat extends ClaimField {
  override def attemptApply(value: JsValue): Option[ClaimValue] =
    value.asOpt[Long].map(apply)

  override val name: String = "nbf"
}

case class Jti(value: String) extends ClaimValue {
  override val field: Field = Jti
  override val jsValue: JsValue = JsString(value)
}

object Jti extends ClaimField {
  override def attemptApply(value: JsValue): Option[ClaimValue] =
    value.asOpt[String].map(apply)

  override val name: String = "jti"
}