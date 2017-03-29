package io.igl.jwt

/**
 * A container used to represent an algorithm.
 */
trait Algorithm {
  def name: String
}

object Algorithm {

  case object HS256 extends Algorithm {
    override val name = "HS256"
    override def toString = "HmacSHA256"
  }

  case object HS384 extends Algorithm {
    override val name = "HS384"
    override def toString = "HmacSHA384"
  }

  case object HS512 extends Algorithm {
    override val name = "HS512"
    override def toString = "HmacSHA512"
  }

  case object RS256 extends Algorithm {
    override val name = "RS256"
    override def toString = "SHA256withRSA"
  }

  case object NONE extends Algorithm {
    override val name = "none"
  }

  /**
   * Tries to find an implemented algorithm that matches a string
   * @param name the string used by the jwt header alg to represent an algorithm
   * @return returns an Algorithm wrapped in Some on success, otherwise None
   */
  def getAlgorithm(name: String): Option[Algorithm] = name match {
    case HS256.name => Some(HS256)
    case NONE.name => Some(NONE)
    case HS384.name => Some(HS384)
    case HS512.name => Some(HS512)
    case RS256.name => Some(RS256)
    case _ => None
  }

}
