/*
 *
 *  Copyright 2015 Netflix, Inc.
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */

using System;
using System.Collections.Generic;
using System.Linq;
using FIDO.Threatfeeds.FIDO.Support.ErrorHandling;
using FIDO.Threatfeeds.FIDO.Support.FidoDB;
using FIDO.Threatfeeds.FIDO.Support.VirusTotal.NET;

namespace FIDO.Threatfeeds.FIDO.Support.Threat.Feeds
{
  public static class ThreatFeedsHash
  {
    public static FidoReturnValues VtHashReturnValues(FidoReturnValues lFidoReturnValues)
    {
      var vtHashReport = FeedsVirusTotal.VirusTotalHash(lFidoReturnValues.Hash);
      lFidoReturnValues = GetCurrentDetector(lFidoReturnValues, vtHashReport, null);
      return lFidoReturnValues;
    }

    public static FidoReturnValues TgHashReturnValues(FidoReturnValues lFidoReturnValues)
    {
      var tgHashReport = SendHashToThreatGRID(lFidoReturnValues.Hash);
      lFidoReturnValues = GetCurrentDetector(lFidoReturnValues, null, tgHashReport);
      return lFidoReturnValues;
    }

    private static FidoReturnValues GetCurrentDetector(FidoReturnValues lFidoReturnValues, List<FileReport> vtHashReport,ThreatGRIDReturnValues tgHashReport)
    {
      if (lFidoReturnValues.Cyphort != null)
      {
        if (vtHashReport != null) lFidoReturnValues.Cyphort.VirusTotal.MD5HashReturn = vtHashReport;
        if (tgHashReport != null) lFidoReturnValues.Cyphort.ThreatGRID = tgHashReport;
        return lFidoReturnValues;
      }
      if (lFidoReturnValues.CB?.Alert != null)
      {
        if (vtHashReport != null) lFidoReturnValues.CB.Alert.VirusTotal.MD5HashReturn = vtHashReport;
        if (tgHashReport != null) lFidoReturnValues.CB.Alert.ThreatGRID = tgHashReport;
        return lFidoReturnValues;
      }
      if (lFidoReturnValues.SentinelOne != null)
      {
        if (vtHashReport != null) lFidoReturnValues.SentinelOne.VirusTotal.MD5HashReturn = vtHashReport;
        if (tgHashReport != null) lFidoReturnValues.SentinelOne.ThreatGRID = tgHashReport;
        return lFidoReturnValues;
      }
      if (lFidoReturnValues.ProtectWise != null)
      {
        if (vtHashReport != null) lFidoReturnValues.ProtectWise.VirusTotal.MD5HashReturn = vtHashReport;
        if (tgHashReport != null) lFidoReturnValues.ProtectWise.ThreatGRID = tgHashReport;
        return lFidoReturnValues;
      }
      return null;
    }

    private static ThreatGRIDReturnValues SendHashToThreatGRID(List<string> Hashes)
    {
      //todo: move this to the db
      const int iDays = -180;
      var threatGRID = new ThreatGRIDReturnValues();
      if (Hashes == null) return threatGRID;
      threatGRID.HashSearch = new List<ThreatGridSearchConfigClass.ThreatGRID_Search>();

      try
      {
        foreach (var md5 in Hashes)
        {
          if (string.IsNullOrEmpty(md5)) continue;
          var hashsearch = FeedsThreatGRID.SearchInfo(md5, ThreatArtifactEnum.Hash, iDays);
          if (hashsearch == null) continue;
          threatGRID.HashSearch.Add(hashsearch);
          if (threatGRID.HashSearch == null) continue;
          if (!threatGRID.HashSearch.Any()) continue;

          //while (threatGRID.HashSearch.Data.CurrentItemCount < 50)
          //{
          //  if (iDays < -364) break;
          //  iDays = (Int16)(iDays * 2);
          //  threatGRID.HashSearch = Feeds_ThreatGRID.SearchInfo(md5, true, iDays);
          //}

          if (threatGRID.HashSearch.Count > 0 && threatGRID.HashSearch[0].Data.Items.Count > 0)
          {
            Console.WriteLine(@"Successfully found ThreatGRID hash data (" + threatGRID.HashSearch.Count + @" records)... storing in Fido.");
            if (threatGRID.HashThreatInfo == null)
            {
              threatGRID.HashThreatInfo = new List<ThreatGridThreatConfigClass.ThreatGridThreatInfo>();
            }

            for (var i = 0; i < threatGRID.HashSearch.Count; i++)
            {
              foreach (var t in threatGRID.HashSearch[i].Data.Items)
              {
                //todo: move this to the db
                if (i >= 50) continue;
                if (string.IsNullOrEmpty(t.HashID)) continue;
                var x = FeedsThreatGRID.ThreatInfo(t.HashID);
                if (x == null) continue;
                threatGRID.HashThreatInfo.Add(x);
              }
            }
          }
        }
        return threatGRID;

      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Threatfeed Hash area:" + e + " " + iDays + " " + threatGRID.HashSearch.Count);
      }
      return threatGRID;
    }
  }
}
