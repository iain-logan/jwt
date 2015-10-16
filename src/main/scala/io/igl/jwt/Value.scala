package io.igl.jwt

import play.api.libs.json._

/**
 * A representation of a jwt field value.
 */
trait Value {

  /** The field to which a value belongs **/
  val field: Field

  /** The real value of a field **/
  val value: Any

  /** The value of a field represented as json **/
  val jsValue: JsValue

}

abstract class JwtValue extends Value
