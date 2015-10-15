package io.igl.jwt

import scala.reflect.ClassTag

trait Jwt {
  def getHeader[T <: HeaderValue: ClassTag]: Option[T]
  def getClaim[T <: ClaimValue: ClassTag]: Option[T]
  def encodedAndSigned(secret: String): String
}