// Decompiled with JetBrains decompiler
// Type: VirusTotalNET.UnixTimeHelper
// Assembly: VirusTotal.NET, Version=1.3.1.0, Culture=neutral, PublicKeyToken=null
// MVID: 2B160AD8-F9AD-46F3-A2B1-F9B9E38BD041
// Assembly location: D:\repository\repo\vs2015\Security\FIDO.Threatfeeds\FIDO.Threatfeeds\packages\VirusTotal.NET.1.3.1.0\lib\VirusTotal.NET.dll

using System;

namespace FIDO.Threatfeeds.FIDO.Support.VirusTotal.NET
{
  public static class UnixTimeHelper
  {
    private static DateTime _epoc = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

    public static DateTime FromUnix(double unixTime)
    {
      return UnixTimeHelper._epoc.AddSeconds(unixTime).ToLocalTime();
    }

    public static double FromDateTime(DateTime dateTime)
    {
      return (dateTime - UnixTimeHelper._epoc.ToLocalTime()).TotalSeconds;
    }
  }
}
