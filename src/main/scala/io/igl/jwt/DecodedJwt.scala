package io.igl.jwt

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.codec.binary.Base64
import play.api.libs.json.JsObject
import play.api.libs.json.Json
import scala.reflect.ClassTag
import scala.util.Try

class DecodedJwt(headers_ : Seq[HeaderValue], claims_ : Seq[ClaimValue]) extends Jwt {

  // Sort headers and claims so that if multiple duplicate types are provided, the last header/claim of said type is selected
  private val headers = withOutDuplicateOccurrence(headers_.reverse :+ Alg(Algorithm.NONE)).reverse
  private val claims = withOutDuplicateOccurrence(claims_.reverse).reverse

  private def withOutDuplicateOccurrence(values: Seq[Value]): Seq[Value] = {

    def withOutOccurrence(target: Field, values: Seq[Value]): Seq[Value] = values match {
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

    val encodedHeader: String = DecodedJwt.encodeBase64Url(JsObject(headers.map(_.jsPair)).toString())
    val encodedPayload: String = DecodedJwt.encodeBase64Url(JsObject(claims.map(_.jsPair)).toString())
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

  /** Returns the Base64 decoded version of provided string **/
  private def decodeBase64(subject: String): String = new String(Base64.decodeBase64(subject))

  /** Returns the Base64 url safe encoding of a byte array **/
  private def encodeBase64Url(subject: Array[Byte]): String = Base64.encodeBase64URLSafeString(subject)

  /** Returns the Base64 url safe encoding of a string **/
  private def encodeBase64Url(subject: String): String = encodeBase64Url(subject.getBytes("utf-8"))

  /**
   * Returns the signature of a jwt.
   *
   * @param encodedHeaderAndPayload the encoded header and payload of a jwt
   * @param algorithm the algorithm to be used
   * @param secret the secret to sign with
   * @return a string representing the signature of a jwt
   */
  private def encodedSignature(encodedHeaderAndPayload: String, algorithm: Algorithm, secret: String = ""): String =
    algorithm match {
      case Algorithm.HS256 =>
        val mac: Mac = Mac.getInstance(algorithm.toString)
        mac.init(new SecretKeySpec(secret.getBytes("utf-8"), algorithm.toString))
        encodeBase64Url(mac.doFinal(encodedHeaderAndPayload.getBytes("utf-8")))
      case Algorithm.NONE => encodedHeaderAndPayload
    }

  /**
   * Attempts to construct a DecodedJwt from an encoded jwt.
   *
   * Any fields found in the jwt that are not in either the required set or the ignore set, will cause validation to fail.
   * Including an algorithm field in the requiredHeaders set is not needed, instead use the requiredAlg parameter.
   * Please note that this will not validate exp and nbf claims.
   *
   * @param jwt an encrypted jwt
   * @param secret the secret to use when validating the signature
   * @param requiredAlg the algorithm to require and use when validating the signature
   * @param requiredHeaders the headers the encrypted jwt is required to use
   * @param requiredClaims the claims the encrypted jwt is required to use
   * @param ignoredHeaders the headers to ignore should the encrypted jwt use them
   * @param ignoredClaims the claims to ignore should the encrypted jwt use them
   * @return returns a [[DecodedJwt]] wrapped in [[scala.util.Success]] when successful, otherwise [[scala.util.Failure]]
   */
  def validateEncodedJwt(
    jwt: String,
    secret: String,
    requiredAlg: Algorithm,
    requiredHeaders: Set[HeaderField],
    requiredClaims: Set[ClaimField],
    ignoredHeaders: Set[String] = Set(),
    ignoredClaims: Set[String] = Set()): Try[Jwt] = Try {

    require(requiredHeaders.map(_.name).size == requiredHeaders.size, "Required headers contains field name collisions")
    require(requiredClaims.map(_.name).size == requiredClaims.size, "Required claims contains field name collisions")
    require(!requiredHeaders.contains(Alg), "Alg should not be included in the required headers")

    // Extract the various parts of a JWT
    val parts: (String, String, String) = jwt.split('.') match {
      case Array(header, payload, signature) => (header, payload, signature)
      case _ => throw new IllegalArgumentException("Jwt could not be split into a header, payload, and signature")
    }

    val header    = parts._1
    val payload   = parts._2
    val signature = parts._3

    // Validate headers
    val headerJson = Try {
      Json.parse(decodeBase64(header)) match {
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
            ignoredHeaders.find(_ == field).getOrElse(throw new IllegalArgumentException("Found header that is in neither the required or the ignored set"))
            None
        }
    }

    if (headers.size != requiredHeaders.size + 1)
      throw new IllegalArgumentException("Provided jwt did not contain all required headers")

    // Validate payload
    val payloadJson = Try {
      Json.parse(decodeBase64(payload)) match {
        case header: JsObject => header
        case _ => throw new IllegalArgumentException()
      }
    }.getOrElse(throw new IllegalArgumentException("Decoded header could not be parsed to a JSON object"))

    val claims = payloadJson.fields.flatMap {
      case (field, value) =>
        requiredClaims.find(x => x.name == field) match {
          case Some(requiredClaim) => requiredClaim.attemptApply(value)
          case None =>
            ignoredClaims.find(_ == field).getOrElse(throw new IllegalArgumentException("Found claim that is in neither the required or the ignored set"))
            None
        }
    }

    if (claims.size != requiredClaims.size)
      throw new IllegalArgumentException("Provided jwt did not contain all required headers")

    // Validate signature
    if (claims.size != claims.size)
      throw new IllegalArgumentException("The required claims did not match the encoded jwts claims")

    if (signature.equals(encodedSignature(header + ('.' +: payload), requiredAlg, secret)))
      new DecodedJwt(headers, claims)
    else
      throw new IllegalArgumentException("Signature is incorrect")
  }

}