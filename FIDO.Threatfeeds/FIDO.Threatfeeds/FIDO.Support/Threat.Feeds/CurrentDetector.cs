using System;
using System.Collections.Generic;
using FIDO.Threatfeeds.FIDO.Support.FidoDB;
using FIDO.Threatfeeds.FIDO.Support.VirusTotal.NET;

namespace FIDO.Threatfeeds.FIDO.Support.Threat.Feeds
{
  public class CurrentDetector
  {
    public static FidoReturnValues GetCurrentDetector(FidoReturnValues lFidoReturnValues, List<UrlReport> vtUrlReport)
    {
      if (vtUrlReport == null) throw new ArgumentNullException(nameof(vtUrlReport));

      if (lFidoReturnValues.Cyphort != null)
      {
        lFidoReturnValues.Cyphort.VirusTotal.URLReturn = vtUrlReport;
        return lFidoReturnValues;
      }
      if (lFidoReturnValues.ProtectWise != null)
      {
        lFidoReturnValues.ProtectWise.VirusTotal.URLReturn = vtUrlReport;
        return lFidoReturnValues;
      }
      return null;
    }

    public static FidoReturnValues GetCurrentDetector(FidoReturnValues lFidoReturnValues, List<IPReport> vtIpReport)
    {
      if (vtIpReport == null) throw new ArgumentNullException(nameof(vtIpReport));
      if (lFidoReturnValues.CB?.Alert != null)
      {
        lFidoReturnValues.CB.Alert.VirusTotal.IPReturn = vtIpReport;
        return lFidoReturnValues;
      }
      if (lFidoReturnValues.Cyphort != null)
      {
        lFidoReturnValues.Cyphort.VirusTotal.IPReturn = vtIpReport;
        return lFidoReturnValues;
      }
      if (lFidoReturnValues.ProtectWise != null)
      {
        lFidoReturnValues.ProtectWise.VirusTotal.IPReturn = vtIpReport;
        return lFidoReturnValues;
      }
      if (lFidoReturnValues.Niddel != null)
      {
        lFidoReturnValues.Niddel.VirusTotal.IPReturn = vtIpReport;
        return lFidoReturnValues;
      }
      if (lFidoReturnValues.PaloAlto != null)
      {
        lFidoReturnValues.PaloAlto.VirusTotal.IPReturn = vtIpReport;
        return lFidoReturnValues;
      }

      return null;
    }

    public static FidoReturnValues GetCurrentDetector(FidoReturnValues lFidoReturnValues, List<DomainReport> vtDomainReport)
    {
      if (vtDomainReport == null) throw new ArgumentNullException(nameof(vtDomainReport));
      if (lFidoReturnValues.CB?.Alert != null)
      {
        lFidoReturnValues.CB.Alert.VirusTotal.DomainReturn = vtDomainReport;
        return lFidoReturnValues;
      }
      if (lFidoReturnValues.Cyphort != null)
      {
        lFidoReturnValues.Cyphort.VirusTotal.DomainReturn = vtDomainReport;
        return lFidoReturnValues;
      }
      if (lFidoReturnValues.ProtectWise != null)
      {
        lFidoReturnValues.ProtectWise.VirusTotal.DomainReturn = vtDomainReport;
        return lFidoReturnValues;
      }
      if (lFidoReturnValues.PaloAlto != null)
      {
        lFidoReturnValues.PaloAlto.VirusTotal.DomainReturn = vtDomainReport;
        return lFidoReturnValues;
      }
      if (lFidoReturnValues.Niddel != null)
      {
        lFidoReturnValues.Niddel.VirusTotal.DomainReturn = vtDomainReport;
        return lFidoReturnValues;
      }

      return null;
    }

    public static FidoReturnValues GetCurrentDetector(FidoReturnValues lFidoReturnValues, ThreatGRIDReturnValues tgRet)
    {
      if (tgRet == null) throw new ArgumentNullException(nameof(tgRet));

      if (lFidoReturnValues.Cyphort != null)
      {
        lFidoReturnValues.Cyphort.ThreatGRID = tgRet;
        return lFidoReturnValues;
      }
      if (lFidoReturnValues.CB?.Alert != null)
      {
        lFidoReturnValues.CB.Alert.ThreatGRID = tgRet;
        return lFidoReturnValues;
      }
      if (lFidoReturnValues.SentinelOne != null)
      {
        lFidoReturnValues.SentinelOne.ThreatGRID = tgRet;
        return lFidoReturnValues;
      }
      if (lFidoReturnValues.ProtectWise != null)
      {
        lFidoReturnValues.ProtectWise.ThreatGRID = tgRet;
        return lFidoReturnValues;
      }
      if (lFidoReturnValues.Niddel != null)
      {
        lFidoReturnValues.Niddel.ThreatGRID = tgRet;
        return lFidoReturnValues;
      }
      return null;
    }

    public static FidoReturnValues GetCurrentDetector(FidoReturnValues lFidoReturnValues, OpenDNSClass odRet)
    {
      if (odRet == null) throw new ArgumentNullException(nameof(odRet));

      if (lFidoReturnValues.Cyphort != null)
      {
        lFidoReturnValues.Cyphort.OpenDNS = odRet;
        return lFidoReturnValues;
      }
      if (lFidoReturnValues.CB?.Alert != null)
      {
        lFidoReturnValues.CB.Alert.OpenDNS = odRet;
        return lFidoReturnValues;
      }
      //todo: update when we can send S1 data to OD
      //if (lFidoReturnValues.SentinelOne != null)
      //{
      //  lFidoReturnValues.SentinelOne. = odRet;
      //  return lFidoReturnValues;
      //}
      if (lFidoReturnValues.ProtectWise != null)
      {
        lFidoReturnValues.ProtectWise.OpenDNS = odRet;
        return lFidoReturnValues;
      }
      if (lFidoReturnValues.Niddel != null)
      {
        lFidoReturnValues.Niddel.OpenDNS = odRet;
        return lFidoReturnValues;
      }
      return null;
    }
  }
}