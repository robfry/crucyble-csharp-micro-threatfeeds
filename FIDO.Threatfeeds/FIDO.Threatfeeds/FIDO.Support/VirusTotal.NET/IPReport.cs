// Decompiled with JetBrains decompiler
// Type: VirusTotalNET.Objects.IPReport
// Assembly: VirusTotal.NET, Version=1.3.1.0, Culture=neutral, PublicKeyToken=null
// MVID: 2B160AD8-F9AD-46F3-A2B1-F9B9E38BD041
// Assembly location: D:\repository\repo\vs2015\Security\FIDO.Threatfeeds\FIDO.Threatfeeds\packages\VirusTotal.NET.1.3.1.0\lib\VirusTotal.NET.dll

using System.Collections.Generic;

namespace FIDO.Threatfeeds.FIDO.Support.VirusTotal.NET
{
  public class IPReport
  {
    public string AsOwner { get; set; }

    public int ASN { get; set; }

    public string Country { get; set; }

    public List<Resolution> Resolutions { get; set; }

    public List<DetectedUrl> DetectedUrls { get; set; }

    public List<Sample> DetectedCommunicatingSamples { get; set; }

    public List<Sample> DetectedDownloadedSamples { get; set; }

    public List<Sample> DetectedReferrerSamples { get; set; }

    public List<Sample> UndetectedCommunicatingSamples { get; set; }

    public List<Sample> UndetectedDownloadedSamples { get; set; }

    /// <summary>
    /// The response code. Use this to determine the status of the report.
    /// </summary>
    public IPReportResponseCode ResponseCode { get; set; }

    /// <summary>
    /// Contains the message that corrosponds to the reponse code.
    /// </summary>
    public string VerboseMsg { get; set; }
  }
}
