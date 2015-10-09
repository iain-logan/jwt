package io.igl.jwt

import play.api.libs.json._
import scala.reflect.runtime.universe._

// JWT potential Header fields
sealed trait JwtFieldValue {
  def field: JwtField
  def value: JsValue
}

sealed trait JwtField {//[T <: Claim[T]] {
  def name: String
}

trait Header extends JwtField {
  def attemptApply(_value: JsLookupResult): Option[HeaderValue]
}
trait HeaderValue extends JwtFieldValue {
  def field: Header
}

case class Typ(_value: String) extends HeaderValue {
  val field = Typ
  val value = JsString(_value)
}

case object Typ extends Header {
  val name: String = "typ"
  def attemptApply(_value: JsLookupResult): Option[Typ] = _value match {
    case _value: JsDefined => _value.asOpt[String] match {
      case Some(_value) => Some(apply(_value))
      case _ => None
    }
    case _ => None
  }
}

case class Alg(_value: Algorithm) extends HeaderValue {
  val field = Alg
  val value = JsString(_value.name)
}

case object Alg extends Header {
  val name: String = "alg"
  def attemptApply(_value: JsLookupResult): Option[Alg] = _value match {
    case _value: JsDefined => _value.asOpt[String] match {
      case Some(_value) => Algorithm.getAlgorithm(_value) match {
        case Some(algorithm) =>
          Some(apply(algorithm))
        case _ => None
      }
    }
    case _ => None
  }
}

case object Cty extends HeaderValue with Header {
  val field = this
  val name = "cty"
  val value = JsString("JWT")
  def attemptApply(_value: JsLookupResult): Option[HeaderValue] = _value match {
    case Cty.value => Some(Cty)
    case _ => None
  }
}


// JWT potential payload fields (claims)
trait Claim extends JwtField {
  def attemptApply(_value: JsLookupResult): Option[ClaimValue]
}
trait ClaimValue extends JwtFieldValue {
  def field: Claim
}

case class Iss(_value: String) extends ClaimValue {
  val field = Iss
  val value = JsString(_value)
}

case object Iss extends Claim {
  val name: String = "iss"
  def attemptApply(_value: JsLookupResult): Option[Iss] = _value match {
    case _value: JsDefined => _value.asOpt[String] match {
      case Some(_value) => Some(apply(_value))
      case _ => None
    }
    case _ => None
  }
}

case class Iat(_value: Long) extends ClaimValue {
  val field = Iat
  val value = JsNumber(_value)
}

case object Iat extends Claim {
  val name: String = "iat"
  def attemptApply(_value: JsLookupResult): Option[Iat] = _value match {
    case _value: JsDefined => _value.asOpt[Long] match {
      case Some(_value) => Some(apply(_value))
      case _ => None
    }
    case _ => None
  }
}

case class Exp(_value: Long) extends ClaimValue {
  val field = Exp
  val value = JsNumber(_value)
}

case object Exp extends Claim {
  val name: String = "exp"
  def attemptApply(_value: JsLookupResult): Option[Exp] = _value match {
    case _value: JsDefined => _value.asOpt[Long] match {
      case Some(_value) => Some(apply(_value))
      case _ => None
    }
    case _ => None
  }
}

case class Sub(_value: String) extends ClaimValue {
  val field = Sub
  val value = JsString(_value)
}

case object Sub extends Claim {
  val name: String = "sub"
  def attemptApply(_value: JsLookupResult): Option[Sub] = _value match {
    case _value: JsDefined => _value.asOpt[String] match {
      case Some(_value) => Some(apply(_value))
      case _ => None
    }
    case _ => None
  }
}

case class Aud(_value: Option[String], _values: Option[Seq[String]]) extends ClaimValue {
  val field = Aud
  val value = (_value, _values) match {
    case (Some(x), None) => JsString(x)
    case (None, Some(xs)) => JsArray(xs.map{s: String => JsString(s)})
    case _ => throw new IllegalArgumentException("Requires either a string or a Seq of strings. Not both or neither.")
  }
}

case object Aud extends Claim {
  val name: String = "aud"
  def apply(_value: String) = new Aud(Some(_value), None)
  def apply(_value: Seq[String]) = new Aud(None, Some(_value))
  def attemptApply(_value: JsLookupResult): Option[Aud] = _value match {
    case _value: JsDefined => _value.asOpt[Seq[String]] match {
      case Some(_value) => Some (apply (_value) )
      case _ => _value.asOpt[String] match {
        case Some (_value) => Some (apply (_value) )
        case _ => None
      }
    }
    case _ => None
  }
}

case class Nbf(_value: Long) extends ClaimValue {
  val field = Nbf
  val value = JsNumber(_value)
}

case object Nbf extends Claim {
  val name: String = "nbf"
  def attemptApply(_value: JsLookupResult): Option[Nbf] = _value match {
    case _value: JsDefined => _value.asOpt[Long] match {
      case Some(_value) => Some(apply(_value))
      case _ => None
    }
    case _ => None
  }
}

case class Jti(_value: String) extends ClaimValue {
  val field = Jti
  val value = JsString(_value)
}

case object Jti extends Claim {
  val name: String = "jti"
  def attemptApply(_value: JsLookupResult): Option[Jti] = _value match {
    case _value: JsDefined => _value.asOpt[String] match {
      case Some(_value) => Some(apply(_value))
      case _ => None
    }
    case _ => None
  }
}

sealed trait Algorithm {
  def name: String
}

object Algorithm {

  case object HS256 extends Algorithm {
    val name = "HS256"
    override def toString = "HmacSHA256"
  }

  case object NONE extends Algorithm {
    val name = "none"
  }

  def getAlgorithm(name: String): Option[Algorithm] = name match {
    case HS256.name => Some(HS256)
    case NONE.name => Some(NONE)
    case _ => None
  }

}

//case class CustomField[T](_name: String, _value: T, _writes: Writes[T]) extends Header with Claim {
//  val name = _name
//  implicit val writes: Writes[T] = _writes
//  val value = Json.toJson(_value)
//}
//
//case object CustomField {
//  def apply(_name: String, _value: String) = new CustomField(_name, _value, Writes(JsString))
//  def apply(_name: String, _value: Boolean) = new CustomField(_name, _value, Writes(JsBoolean))
//}
