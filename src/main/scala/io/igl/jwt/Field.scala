package io.igl.jwt

/**
 * A representation of a jwt field.
 */
trait Field {

  /** The value to use of the field name **/
  val name: String

}

trait JwtField extends Field