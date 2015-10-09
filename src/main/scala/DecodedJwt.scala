package io.igl.jwt

import play.api.libs.json._
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.codec.binary.Base64
import scala.reflect._
//import JwtFields
import scala.collection.immutable.Set

case class DecodedJwt(headers: Set[HeaderValue], claims: Set[ClaimValue]) {

  //def this(headers: Set[HeaderValue], claims: Set[ClaimValue]) = this(headers.map({h: HeaderValue => h.field -> h}).toMap, claims.map({c: ClaimValue => c.field -> c}).toMap)

  def encodedAndSigned(secret: String): String = {
    def pair = (hf: JwtFieldValue) => hf.field.name -> hf.value
    val algorithm: Algorithm = headers.collectFirst({
      case (headerValue: Alg) => headerValue
    }) match {
      case None => throw new IllegalArgumentException("No \"alg\" value provided, use \"none\" if none required");
      case Some(algorithm) => algorithm._value
    }
    val header: JsValue = JsObject(headers.map(pair).toSeq)
    val encodedHeader: String = DecodedJwt.encodeBase64Url(header.toString())
    val encodedPayload: String = DecodedJwt.encodeBase64Url(JsObject(claims.map(pair).toSeq).toString())
    val encodedHeaderAndPayload: String = encodedHeader ++ ('.' +: encodedPayload)
    encodedHeaderAndPayload ++ ('.' +: DecodedJwt.encodedSignature(encodedHeaderAndPayload, algorithm, secret))
  }

  def getHeader[T <: HeaderValue: ClassTag]: Option[T] = {
    headers.collectFirst {
      case target: T => target
    }
  }

  def getClaim[T <: ClaimValue: ClassTag]: Option[T] =
    claims.collectFirst {
      case target: T => target
    }
}

object DecodedJwt {

  def validateEncodedJwt(jwt: String, requiredHeaders: Set[Header], requiredClaims: Set[Claim], secret: String, requiredAlg: Algorithm): Option[DecodedJwt] = {
    require(jwt.contains('.'), "Encoded jwt must contain at least one '.' character")

    // Extract the various sections of a JWT
    val parts: (String, String, String) = jwt.split('.').toList match {
      case header :: payload :: signature :: Nil => (header, payload, signature)
      case _ => throw new IllegalArgumentException("Ill formed")
    }
    val header: String = parts._1
    val payload: String = parts._2
    val signature: String = parts._3

    // Validate headers
    val headers: Set[HeaderValue] =
      Json.parse(decodeBase64(header)) match {
        case header: JsObject =>
          val headers: Set[HeaderValue] = requiredHeaders.flatMap { h =>
            h.attemptApply(header \ h.name)
          }
          if (headers.size != requiredHeaders.size)
            return None
          headers
        case _ => throw new IllegalArgumentException("Decoded header could not be parsed to valid JSON")
      }

    // Validate payload
    val claims: Set[ClaimValue] =
      Json.parse(decodeBase64(payload)) match {
        case payload: JsObject =>
          val claims: Set[ClaimValue] = requiredClaims.flatMap { c =>
            c.attemptApply(payload \ c.name)
          }
          if (claims.size != headers.size)
            return None
          claims
        case _ => throw new IllegalArgumentException("Decoded payload could not be parsed to valid JSON")
      }

    // Validate signature
    val alg: Alg = headers.collectFirst({
      case headerValue: Alg => headerValue
    }).getOrElse(return None)
    if (requiredAlg.equals(alg._value) && signature.equals(encodedSignature(header + ('.' +: payload), alg._value, secret)))
      Some(new DecodedJwt(headers, claims))
    else
      None
  }

  private def decodeBase64(subject: String): String =
    new String(Base64.decodeBase64(subject))

  private def encodeBase64Url(subject: Array[Byte]): String =
    Base64.encodeBase64URLSafeString(subject)

  private def encodeBase64Url(subject: String): String =
    encodeBase64Url(subject.getBytes("utf-8"))

  private def encodedSignature(encodedHeaderAndPayload: String, algorithm: Algorithm, secret: String): String =
    algorithm match {
      case Algorithm.HS256 =>
        val mac: Mac = Mac.getInstance(algorithm.toString)
        mac.init(new SecretKeySpec(secret.getBytes("utf-8"), algorithm.toString))
        encodeBase64Url(mac.doFinal(encodedHeaderAndPayload.getBytes("utf-8")))
      case Algorithm.NONE => encodedHeaderAndPayload
    }

}

