using System;
using FIDO.Threatfeeds.FIDO.Support.ErrorHandling;
using FIDO.Threatfeeds.FIDO.Support.FidoDB;
using FIDO.Threatfeeds.FIDO.Support.RabbitMQ;

namespace FIDO.Threatfeeds.FIDO.Support.Threat.Feeds
{
  public static class DetectorDetect
  {
    public static DetectorEnum? Detect(FidoReturnValues lFidoReturnValues)
    {
      var currentdetector = lFidoReturnValues.CurrentDetector;
      if (currentdetector == null) return null;
      try
      {
        switch (currentdetector)
        {
          case "carbonblack":
            return DetectorEnum.CarbonBlack;
          case "sentinelone":
            return DetectorEnum.SentinelOne;
          case "protectwise":
            return DetectorEnum.ProtectWise;
          case "pan":
            return DetectorEnum.PaloAlto;
          case "niddel":
            return DetectorEnum.Niddel;
          case "cyphort":
            return DetectorEnum.Cyphort;
        }
      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught gathering current detector events:" + e);
      }
      return null;
    }
  }
}