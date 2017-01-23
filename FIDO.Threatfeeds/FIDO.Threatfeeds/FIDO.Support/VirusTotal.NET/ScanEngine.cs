// Decompiled with JetBrains decompiler
// Type: VirusTotalNET.Objects.ScanEngine
// Assembly: VirusTotal.NET, Version=1.3.1.0, Culture=neutral, PublicKeyToken=null
// MVID: 2B160AD8-F9AD-46F3-A2B1-F9B9E38BD041
// Assembly location: D:\repository\repo\vs2015\Security\FIDO.Threatfeeds\FIDO.Threatfeeds\packages\VirusTotal.NET.1.3.1.0\lib\VirusTotal.NET.dll

using System;
using System.Globalization;
using RestSharp.Deserializers;

namespace FIDO.Threatfeeds.FIDO.Support.VirusTotal.NET
{
  public class ScanEngine
  {
    /// <summary>True if the engine flagged the resource.</summary>
    public bool Detected { get; set; }

    /// <summary>Version of the engine.</summary>
    public string Version { get; set; }

    /// <summary>Contains the name of the malware, if any.</summary>
    public string Result { get; set; }

    [DeserializeAs(Name = "update")]
    public string UpdateString
    {
      get
      {
        return this.UpdateDate.ToString();
      }
      set
      {
        DateTime result;
        if (!DateTime.TryParseExact(value, "yyyyMMdd", (IFormatProvider) CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out result))
          return;
        this.UpdateDate = result;
      }
    }

    /// <summary>The date of the latest signatures of the engine.</summary>
    public DateTime UpdateDate { get; set; }
  }
}
