package io.igl.jwt

import java.nio.charset.StandardCharsets.UTF_8
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.codec.binary.Base64
import play.api.libs.json.JsObject
import play.api.libs.json.Json
import scala.reflect.ClassTag
import scala.util.Try

/**
 * A class representing a decoded jwt.
 *
 * When an [[Alg]] value is omitted it defaults to none. Where multiple headers or claims with the same field name are
 * provided, the last occurrence is used.
 *
 * @param headers_ the values of the headers to be set
 * @param claims_ the values of the claims to be set
 */
class DecodedJwt(headers_ : Seq[HeaderValue], claims_ : Seq[ClaimValue]) extends Jwt {

  // Sort headers and claims so that if multiple duplicate types are provided, the last header/claim of said type is selected
  private val headers = withOutDuplicateOccurrence(headers_.reverse :+ Alg(Algorithm.NONE)).reverse
  private val claims = withOutDuplicateOccurrence(claims_.reverse).reverse

  private def withOutDuplicateOccurrence(values: Seq[JwtValue]): Seq[JwtValue] = {

    def withOutOccurrence(target: JwtField, values: Seq[JwtValue]): Seq[JwtValue] = values match {
      case Seq() => Seq()
      case v +: vs if v.field.name == target.name => withOutOccurrence(target, vs)
      case v +: vs => v +: withOutOccurrence(target, vs)
    }

    values match {
      case Seq() => Seq()
      case v +: vs => v +: withOutDuplicateOccurrence(withOutOccurrence(v.field, vs))
    }
  }

  override def getHeader[T <: HeaderValue: ClassTag]: Option[T] = headers.collectFirst {
      case header: T => header.asInstanceOf[T]
    }

  override def getClaim[T <: ClaimValue: ClassTag]: Option[T] = claims.collectFirst {
      case claim: T => claim.asInstanceOf[T]
    }

  private val algorithm = getHeader[Alg].map(_.value).get

  def encodedAndSigned(secret: String): String = {
    encodedAndSigned(secret.getBytes(UTF_8))
  }

  def encodedAndSigned(secret: Array[Byte]): String = {
    def jsAssign(value: JwtValue) = value.field.name -> value.jsValue

    val encodedHeader: String = DecodedJwt.encodeBase64Url(JsObject(headers.map(jsAssign)).toString())
    val encodedPayload: String = DecodedJwt.encodeBase64Url(JsObject(claims.map(jsAssign)).toString())
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

  override def toString: String =
    "DecodedJwt(" + headers.toString() + ", " + claims.toString() + ")"
}

object DecodedJwt {

  /** Returns the Base64 decoded version of provided string **/
  private def decodeBase64(subject: String, charset: String): String = new String(Base64.decodeBase64(subject), charset)

  /** Returns the Base64 url safe encoding of a byte array **/
  private def encodeBase64Url(subject: Array[Byte]): String = Base64.encodeBase64URLSafeString(subject)

  /** Returns the Base64 url safe encoding of a string **/
  private def encodeBase64Url(subject: String): String = encodeBase64Url(subject.getBytes("utf-8"))

  /**
    * Returns the signature of a jwt.
    *
    * @param encodedHeaderAndPayload the encoded header and payload of a jwt
    * @param algorithm               the algorithm to be used
    * @param secret                  the secret to sign with
    * @return a string representing the signature of a jwt
    */
  private def encodedSignature(encodedHeaderAndPayload: String, algorithm: Algorithm, secret: Array[Byte] = Array()): String = {
    import io.igl.jwt.Algorithm._

    def hmac(alg: Algorithm) = {
      val mac: Mac = Mac.getInstance(alg.toString)
      mac.init(new SecretKeySpec(secret, alg.toString))
      encodeBase64Url(mac.doFinal(encodedHeaderAndPayload.getBytes("utf-8")))
    }

    algorithm match {
      case HS256 => hmac(HS256)
      case HS384 => hmac(HS384)
      case HS512 => hmac(HS512)
      case NONE => ""
    }
  }

  private def constantTimeIsEqual(as: Array[Byte], bs: Array[Byte]): Boolean = {
    as.length == bs.length match {
      case true => (as zip bs).foldLeft (0) {(r, ab) => r + (ab._1 ^ ab._2)} == 0
      case _ => false
    }
  }

  /**
    * This method uses the underlying method {@link #validateEncodedJwtWithEncodedSecret(String,Array[Byte],Algorithm,Set[HeaderField],Set[ClaimField],Set[String],Set[String],Option[Iss],Option[Aud], Option[Iat], Option[Sub],Option[Jti],String)},
    * by providing the secret with {@link String#getBytes(StandardCharsets#UTF_8)}
    */
  def validateEncodedJwt(
                          jwt: String,
                          key: String,
                          requiredAlg: Algorithm,
                          requiredHeaders: Set[HeaderField],
                          requiredClaims: Set[ClaimField],
                          ignoredHeaders: Set[String] = Set(),
                          ignoredClaims: Set[String] = Set(),
                          iss: Option[Iss] = None,
                          aud: Option[Aud] = None,
                          iat: Option[Iat] = None,
                          sub: Option[Sub] = None,
                          jti: Option[Jti] = None,
                          charset: String = "UTF-8"): Try[Jwt] = {
    validateEncodedJwtWithEncodedSecret(
                                        jwt,
                                        key.getBytes(UTF_8),
                                        requiredAlg,
                                        requiredHeaders,
                                        requiredClaims,
                                        ignoredHeaders,
                                        ignoredClaims,
                                        iss,
                                        aud,
                                        iat,
                                        sub,
                                        jti,
                                        charset)
  }

  /**
    * Attempts to construct a DecodedJwt from an encoded jwt.
    *
    * Any fields found in the jwt that are not in either the required set or the ignore set, will cause validation to fail.
    * Including an algorithm field in the requiredHeaders set is not needed, instead use the requiredAlg parameter.
    *
    * @param jwt             an encrypted jwt
    * @param key             the key to use when validating the signature
    * @param requiredAlg     the algorithm to require and use when validating the signature
    * @param requiredHeaders the headers the encrypted jwt is required to use
    * @param requiredClaims  the claims the encrypted jwt is required to use
    * @param ignoredHeaders  the headers to ignore should the encrypted jwt use them
    * @param ignoredClaims   the claims to ignore should the encrypted jwt use them
    * @param iss             used optionally, when you want to only validate a jwt where its required iss claim is equal to this
    * @param aud             used optionally, when you want to only validate a jwt where its required aud claim is equal to this
    * @param iat             used optionally, when you want to only validate a jwt where its required iat claim is equal to this
    * @param sub             used optionally, when you want to only validate a jwt where its required sub claim is equal to this
    * @param jti             used optionally, when you want to only validate a jwt where its required jti claim is equal to this
    * @return returns a [[DecodedJwt]] wrapped in Success when successful, otherwise Failure
    */
  def validateEncodedJwtWithEncodedSecret(
                          jwt: String,
                          key: Array[Byte],
                          requiredAlg: Algorithm,
                          requiredHeaders: Set[HeaderField],
                          requiredClaims: Set[ClaimField],
                          ignoredHeaders: Set[String] = Set(),
                          ignoredClaims: Set[String] = Set(),
                          iss: Option[Iss] = None,
                          aud: Option[Aud] = None,
                          iat: Option[Iat] = None,
                          sub: Option[Sub] = None,
                          jti: Option[Jti] = None,
                          charset: String = "UTF-8"): Try[Jwt] = Try {

    require(requiredHeaders.map(_.name).size == requiredHeaders.size, "Required headers contains field name collisions")
    require(requiredClaims.map(_.name).size == requiredClaims.size, "Required claims contains field name collisions")
    require(!requiredHeaders.contains(Alg), "Alg should not be included in the required headers")

    // Extract the various parts of a JWT
    val parts: (String, String, String) = jwt.split('.') match {
      case Array(header, payload, signature) => (header, payload, signature)
      case Array(header, payload) => (header, payload, "")
      case _ => throw new IllegalArgumentException("Jwt could not be split into a header, payload, and signature")
    }

    val header    = parts._1
    val payload   = parts._2
    val signature = parts._3

    // Validate headers
    val headerJson = Try {
      Json.parse(decodeBase64(header, charset)) match {
        case header: JsObject => header
        case _ => throw new IllegalArgumentException()
      }
    }.getOrElse(throw new IllegalArgumentException("Decoded header could not be parsed to a JSON object"))

    val headers = headerJson.fields.flatMap {
      case (Alg.name, value) => Alg.attemptApply(value).map {
        case alg if alg.value == requiredAlg => alg
        case _ => throw new IllegalArgumentException("Given jwt uses a different algorithm ")
      }.orElse(throw new IllegalArgumentException("Algorithm values did not match"))
      case (field, value) =>
        requiredHeaders.find(x => x.name == field) match {
          case Some(requiredHeader) => requiredHeader.attemptApply(value)
          case None =>
            ignoredHeaders.find(_ == field).
              getOrElse(throw new IllegalArgumentException("Found header that is in neither the required or ignored sets"))
            None
        }
    }

    if (headers.size != requiredHeaders.size + 1)
      throw new IllegalArgumentException("Provided jwt did not contain all required headers")

    // Validate payload
    val payloadJson = Try {
      Json.parse(decodeBase64(payload, charset)) match {
        case header: JsObject => header
        case _ => throw new IllegalArgumentException()
      }
    }.getOrElse(throw new IllegalArgumentException("Decoded header could not be parsed to a JSON object"))

    /** Time in seconds since 1970-01-01T00:00:00Z UTC **/
    def now: Long = System.currentTimeMillis / 1000

    val claims = payloadJson.fields.flatMap {
      case (field, value) =>
        requiredClaims.find(x => x.name == field) match {
          case Some(requiredClaim) => requiredClaim.attemptApply(value).map {
            case exp: Exp =>
              now < exp.value match {
                case true  => exp
                case false => throw new IllegalArgumentException("Jwt has expired")
              }
            case nbf: Nbf =>
              now > nbf.value match {
                case true  => nbf
                case false => throw new IllegalArgumentException("Jwt is not yet valid")
              }
            case fIss: Iss =>
              iss.map(_.equals(fIss) match {
                case true => fIss
                case false => throw new IllegalArgumentException("Iss didn't match required iss")
              }).getOrElse(fIss)
            case fAud: Aud =>
              aud.map(_.equals(fAud) match {
                case true => fAud
                case false => throw new IllegalArgumentException("Aud didn't match required aud")
              }).getOrElse(fAud)
            case fIat: Iat =>
              iat.map(_.equals(fIat) match {
                case true => fIat
                case false => throw new IllegalArgumentException("Iat didn't match required iat")
              }).getOrElse(fIat)
            case fSub: Sub =>
              sub.map(_.equals(fSub) match {
                case true => fSub
                case false => throw new IllegalArgumentException("Sub didn't match required sub")
              }).getOrElse(fSub)
            case fJti: Jti =>
              jti.map(_.equals(fJti) match {
                case true => fJti
                case false => throw new IllegalArgumentException("Jti didn't match required jti")
              }).getOrElse(fJti)
            case claim => claim
          }
          case None =>
            ignoredClaims.find(_ == field).
              getOrElse(throw new IllegalArgumentException("Found claim that is in neither the required or ignored sets"))
            None
        }
    }

    if (claims.size != requiredClaims.size)
      throw new IllegalArgumentException("Provided jwt did not contain all required claims")

    // Validate signature
    val correctSignature = encodedSignature(header + ('.' +: payload), requiredAlg, key)

    if (constantTimeIsEqual(signature.getBytes("utf-8"), correctSignature.getBytes("utf-8")))
      new DecodedJwt(headers, claims)
    else
      throw new IllegalArgumentException("Signature is incorrect")
  }

}
