package io.igl.jwt

import play.api.libs.json._
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.codec.binary.Base64
import scala.reflect._
import scala.util.{Success, Try}

case class DecodedJwt(headers: List[HeaderValue], claims: List[ClaimValue], algorithm: Algorithm = Algorithm.NONE) {

  require(!containsField(Alg, headers), "You need not include the algorithm header in the header set, it is added by" +
    "default. The value of the algorithm header defaults to NONE, but can be set to another value should you need to " +
    "through the algorithm parameter")
  require(checkFields(headers), "JWT header types must not occur more than once")
  require(checkFields(claims), "JWT claim types must not occur more than once")

  private def containsField(field: JwtField, fields: List[JwtFieldValue]): Boolean = fields match {
    case Nil => false
    case f :: fs => f.field.equals(field) || containsField(field, fs)
  }

  private def checkFields(fields: List[JwtFieldValue]): Boolean = fields match {
    case Nil => true
    case f :: fs => !containsField(f.field, fs) && checkFields(fs)
  }

  def getHeader[T <: HeaderValue: ClassTag]: Option[T] = (Alg(algorithm) :: headers).collectFirst {
    case target: T => target
  }

  def getClaim[T <: ClaimValue: ClassTag]: Option[T] = claims.collectFirst {
    case target: T => target
  }

  def encodedAndSigned(secret: String): String = {
    def pairUp = (f: JwtFieldValue) => f.field.name -> f.value

    val encodedHeader: String = DecodedJwt.encodeBase64Url(JsObject((Alg(algorithm) :: headers).map(pairUp)).toString())
    val encodedPayload: String = DecodedJwt.encodeBase64Url(JsObject(claims.map(pairUp)).toString())
    val encodedHeaderAndPayload: String = encodedHeader ++ ('.' +: encodedPayload)

    encodedHeaderAndPayload ++ ('.' +: DecodedJwt.encodedSignature(encodedHeaderAndPayload, algorithm, secret))
  }

}

object DecodedJwt {

  private def decodeBase64(subject: String): String = new String(Base64.decodeBase64(subject))

  private def encodeBase64Url(subject: Array[Byte]): String = Base64.encodeBase64URLSafeString(subject)

  private def encodeBase64Url(subject: String): String = encodeBase64Url(subject.getBytes("utf-8"))

  private def encodedSignature(encodedHeaderAndPayload: String, algorithm: Algorithm, secret: String): String =
    algorithm match {
      case Algorithm.HS256 =>
        val mac: Mac = Mac.getInstance(algorithm.toString)
        mac.init(new SecretKeySpec(secret.getBytes("utf-8"), algorithm.toString))
        encodeBase64Url(mac.doFinal(encodedHeaderAndPayload.getBytes("utf-8")))
      case Algorithm.NONE => encodedHeaderAndPayload
    }

  def validateEncodedJwt(jwt: String, requiredHeaders: List[Header], requiredClaims: List[Claim], secret: String, requiredAlg: Algorithm): Try[DecodedJwt] = Try {

    // Extract the various parts of a JWT
    val parts: (String, String, String) = jwt.split('.').toList match {
      case header :: payload :: signature :: Nil => (header, payload, signature)
      case _ => throw new IllegalArgumentException("Jwt could not be split into a header, payload, and signature")
    }

    val header    = parts._1
    val payload   = parts._2
    val signature = parts._3

    // Validate headers
    val headerJson = Json.parse(decodeBase64(header)) match {
      case header: JsObject => header
      case _ => throw new IllegalArgumentException("Decoded header could not be parsed to valid JSON")
    }

    val headers = requiredHeaders.flatMap { h => h.attemptApply(headerJson \ h.name) }

    val algorithm = Alg.attemptApply(headerJson \ Alg.name)
      .getOrElse(throw new IllegalArgumentException("Given encoded jwt did not contain an algorithm header"))

    if (!algorithm._value.equals(requiredAlg))
      throw new IllegalArgumentException("Algorithm values did not match")

    if (headers.size != requiredHeaders.size)
      throw new IllegalArgumentException("The required headers did not match the encoded jwts headers")

    // Validate payload
    val claims = Json.parse(decodeBase64(payload)) match {
      case payload: JsObject => requiredClaims.flatMap { c => c.attemptApply(payload \ c.name) }
      case _ => throw new IllegalArgumentException("Decoded payload could not be parsed to valid JSON")
    }

    // Validate signature
    if (claims.size != claims.size)
      throw new IllegalArgumentException("The required claims did not match the encoded jwts claims")

    if (signature.equals(encodedSignature(header + ('.' +: payload), requiredAlg, secret)))
      DecodedJwt(headers, claims, algorithm._value)
    else
      throw new IllegalArgumentException("Signature is incorrect")
  }

}

