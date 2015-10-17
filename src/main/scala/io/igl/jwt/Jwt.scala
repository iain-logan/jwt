package io.igl.jwt

import scala.reflect.ClassTag

trait Jwt {

  /**
   * Attempts to return a [[HeaderValue]] of the provided type.
   * @tparam T the type of a potential header
   * @return returns None if no header found, otherwise a header of the same type as requested wrapped in Some
   */
  def getHeader[T <: HeaderValue: ClassTag]: Option[T]

  /**
   * Attempts to return a [[ClaimValue]] of the provided type.
   * @tparam T the type of a potential claim
   * @return returns None if no claim found, otherwise a claim of the same type as requested wrapped in Some
   */
  def getClaim[T <: ClaimValue: ClassTag]: Option[T]

  /**
   * Returns an encoded representation of the decoded jwt, signed with a signature generated with the secret provided.
   * @param secret the secret to use when signing the jwt
   * @return an encoded representation of the decoded jwt
   */
  def encodedAndSigned(secret: String): String

}
