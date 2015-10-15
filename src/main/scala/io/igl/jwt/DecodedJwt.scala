package io.igl.jwt

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import org.apache.commons.codec.binary.Base64
import play.api.libs.json.JsObject
import play.api.libs.json.Json
import scala.reflect.ClassTag
import scala.util.Try

class DecodedJwt(headers_ : HeaderValue*)(claims_ : ClaimValue*) extends Jwt {

  // Sort headers and claims so that if multiple duplicate types are provided, the last header/claim of said type is selected
  private val headers = (Alg(Algorithm.NONE) +: headers_).reverse.groupBy(_.getClass).map(_._2.head).toSet
  private val claims = claims_.reverse.groupBy(_.getClass).map(_._2.head).toSet

  override def getHeader[T <: HeaderValue: ClassTag]: Option[T] = headers.collectFirst {
      case header: T => header.asInstanceOf[T]
    }

  override def getClaim[T <: ClaimValue: ClassTag]: Option[T] = claims.collectFirst {
      case claim: T => claim.asInstanceOf[T]
    }

  private val algorithm = getHeader[Alg].map(_.value).get

  def encodedAndSigned(secret: String): String = {

    val encodedHeader: String = DecodedJwt.encodeBase64Url(JsObject(headers.map(_.jsPair).toSeq).toString())
    val encodedPayload: String = DecodedJwt.encodeBase64Url(JsObject(claims.map(_.jsPair).toSeq).toString())
    val encodedHeaderAndPayload: String = encodedHeader ++ ('.' +: encodedPayload)

    encodedHeaderAndPayload ++ ('.' +: DecodedJwt.encodedSignature(encodedHeaderAndPayload, algorithm, secret))
  }

  private def canEqual(other: Any): Boolean = other.isInstanceOf[DecodedJwt]

  override def equals(other: Any): Boolean = other match {
    case that: DecodedJwt =>
      (that canEqual this) &&
      (headers == that.headers) &&
      (claims == that.claims)
    case _ => false
  }

  override def hashCode(): Int = headers.hashCode() ^ claims.hashCode()
}

object DecodedJwt {

  private def decodeBase64(subject: String): String = new String(Base64.decodeBase64(subject))

  private def encodeBase64Url(subject: Array[Byte]): String = Base64.encodeBase64URLSafeString(subject)

  private def encodeBase64Url(subject: String): String = encodeBase64Url(subject.getBytes("utf-8"))

  private def encodedSignature(encodedHeaderAndPayload: String, algorithm: Algorithm, secret: String = ""): String =
    algorithm match {
      case Algorithm.HS256 =>
        val mac: Mac = Mac.getInstance(algorithm.toString)
        mac.init(new SecretKeySpec(secret.getBytes("utf-8"), algorithm.toString))
        encodeBase64Url(mac.doFinal(encodedHeaderAndPayload.getBytes("utf-8")))
      case Algorithm.NONE => encodedHeaderAndPayload
    }

  def validateEncodedJwt(jwt: String,
                         secret: String,
                         requiredAlg: Algorithm)
                        (requiredHeaders_ : HeaderField*)
                        (requiredClaims : ClaimField*): Try[Jwt] = Try {

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

    val algorithm = (headerJson \ Alg.name).toOption.flatMap(Alg.attemptApply).
      getOrElse(throw new IllegalArgumentException("Given encoded jwt did not contain an algorithm header"))

    if (!algorithm.value.equals(requiredAlg))
      throw new IllegalArgumentException("Algorithm values did not match")

    val requiredHeaders = algorithm.field +: requiredHeaders_

    val headers = requiredHeaders.flatMap { h => (headerJson \ h.name).toOption.flatMap(h.attemptApply) }

    if (headers.size != requiredHeaders.size)
      throw new IllegalArgumentException("The required headers did not match the encoded jwts headers")

    // Validate payload
    val claims = Json.parse(decodeBase64(payload)) match {
      case payload: JsObject => requiredClaims.flatMap { c => (payload \ c.name).toOption.flatMap(c.attemptApply) }
      case _ => throw new IllegalArgumentException("Decoded payload could not be parsed to valid JSON")
    }

    // Validate signature
    if (claims.size != claims.size)
      throw new IllegalArgumentException("The required claims did not match the encoded jwts claims")

    if (signature.equals(encodedSignature(header + ('.' +: payload), requiredAlg, secret)))
      new DecodedJwt (algorithm +: headers :_*) (claims: _*)
    else
      throw new IllegalArgumentException("Signature is incorrect")
  }

}