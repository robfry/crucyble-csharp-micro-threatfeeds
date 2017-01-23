// Decompiled with JetBrains decompiler
// Type: VirusTotalNET.Objects.WotInfo
// Assembly: VirusTotal.NET, Version=1.3.1.0, Culture=neutral, PublicKeyToken=null
// MVID: 2B160AD8-F9AD-46F3-A2B1-F9B9E38BD041
// Assembly location: D:\repository\repo\vs2015\Security\FIDO.Threatfeeds\FIDO.Threatfeeds\packages\VirusTotal.NET.1.3.1.0\lib\VirusTotal.NET.dll

using RestSharp.Deserializers;

namespace FIDO.Threatfeeds.FIDO.Support.VirusTotal.NET
{
  public class WotInfo
  {
    [DeserializeAs(Name = "Child safety")]
    public string ChildSafety { get; set; }

    public string Privacy { get; set; }

    public string Trustworthiness { get; set; }

    [DeserializeAs(Name = "Vendor reliability")]
    public string VendorReliability { get; set; }
  }
}
