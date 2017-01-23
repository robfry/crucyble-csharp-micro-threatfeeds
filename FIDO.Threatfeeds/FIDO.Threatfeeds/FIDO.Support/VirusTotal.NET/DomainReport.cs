// Decompiled with JetBrains decompiler
// Type: VirusTotalNET.Objects.DomainReport
// Assembly: VirusTotal.NET, Version=1.3.1.0, Culture=neutral, PublicKeyToken=null
// MVID: 2B160AD8-F9AD-46F3-A2B1-F9B9E38BD041
// Assembly location: D:\repository\repo\vs2015\Security\FIDO.Threatfeeds\FIDO.Threatfeeds\packages\VirusTotal.NET.1.3.1.0\lib\VirusTotal.NET.dll

using System;
using System.Collections.Generic;
using RestSharp.Deserializers;

namespace FIDO.Threatfeeds.FIDO.Support.VirusTotal.NET
{
  public class DomainReport
  {
    [DeserializeAs(Name = "Alexa category")]
    public string AlexaCategory { get; set; }

    [DeserializeAs(Name = "Alexa domain info")]
    public string AlexaDomainInfo { get; set; }

    [DeserializeAs(Name = "Alexa rank")]
    public int AlexaRank { get; set; }

    [DeserializeAs(Name = "BitDefender category")]
    public string BitDefenderCategory { get; set; }

    [DeserializeAs(Name = "BitDefender domain info")]
    public string BitDefenderDomainInfo { get; set; }

    public List<string> Categories { get; set; }

    public List<Sample> DetectedCommunicatingSamples { get; set; }

    public List<Sample> DetectedDownloadedSamples { get; set; }

    public List<Sample> DetectedReferrerSamples { get; set; }

    public List<DetectedUrl> DetectedUrls { get; set; }

    [DeserializeAs(Name = "Dr.Web category")]
    public string DrWebCategory { get; set; }

    [DeserializeAs(Name = "Opera domain info")]
    public string OperaDomainInfo { get; set; }

    public List<string> Pcaps { get; set; }

    public List<Resolution> Resolutions { get; set; }

    /// <summary>
    /// The response code. Use this to determine the status of the report.
    /// </summary>
    public ReportResponseCode ResponseCode { get; set; }

    [DeserializeAs(Name = "domain_siblings")]
    public List<string> Subdomains { get; set; }

    [DeserializeAs(Name = "TrendMicro category")]
    public string TrendMicroCategory { get; set; }

    public List<Sample> UndetectedCommunicatingSamples { get; set; }

    public List<Sample> UndetectedDownloadedSamples { get; set; }

    public List<Sample> UndetectedReferrerSamples { get; set; }

    /// <summary>
    /// Contains the message that corrosponds to the reponse code.
    /// </summary>
    public string VerboseMsg { get; set; }

    [DeserializeAs(Name = "Websense ThreatSeeker category")]
    public string WebsenseThreatSeekerCategory { get; set; }

    [DeserializeAs(Name = "Webutation domain info")]
    public WebutationInfo WebutationDomainInfo { get; set; }

    [DeserializeAs(Name = "whois")]
    public string WhoIs { get; set; }

    [DeserializeAs(Name = "whois_timestamp")]
    public string WhoIsTimestamp { get; set; }

    public DateTime? WhoIsDateTime
    {
      get
      {
        if (string.IsNullOrWhiteSpace(this.WhoIsTimestamp))
          return new DateTime?();
        return new DateTime?(UnixTimeHelper.FromUnix(double.Parse(this.WhoIsTimestamp)));
      }
    }

    [DeserializeAs(Name = "WOT domain info")]
    public WotInfo WOTDomainInfo { get; set; }
  }
}
