package io.igl.jwt

import play.api.libs.json.{JsNumber, JsArray, JsString, JsValue}

/** Scope claim 
  * 
  * Not in JWT specification but required by Google Cloud Platform for example
  * 
  */
case class Scope(value: String) extends ClaimValue {
  override val jsValue = JsString(value)
  override val field: ClaimField = Scope
}

object Scope extends ClaimField {
  override def attemptApply(value: JsValue): Option[Scope] =
    value.asOpt[String].map(apply)
  override val name = "scope"
}
