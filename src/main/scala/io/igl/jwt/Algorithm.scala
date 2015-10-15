package io.igl.jwt

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