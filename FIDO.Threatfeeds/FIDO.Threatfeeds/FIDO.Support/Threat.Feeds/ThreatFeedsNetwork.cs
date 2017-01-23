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
using System.Threading.Tasks;
using FIDO.Threatfeeds.FIDO.Support.API.Endpoints;
using FIDO.Threatfeeds.FIDO.Support.ErrorHandling;
using FIDO.Threatfeeds.FIDO.Support.FidoDB;
using FIDO.Threatfeeds.FIDO.Support.VirusTotal.NET;

namespace FIDO.Threatfeeds.FIDO.Support.Threat.Feeds
{
  static class ThreatFeedsNetwork
  {
    private static readonly string _vtKey = APIEndpoints.PrimaryConfig.host + APIEndpoints.PrimaryConfig.fido_configs_threatfeeds.threatfeed_api.vendor + "?key=\"virustotal\"";

    public static FidoReturnValues VtUrlReturnValues(FidoReturnValues lFidoReturnValues)
    {

      var queryVt = new VirusTotal(_vtKey);
      var urlReport = queryVt.GetUrlReports(lFidoReturnValues.Url, true);

      lFidoReturnValues = CurrentDetector.GetCurrentDetector(lFidoReturnValues, urlReport);

      return lFidoReturnValues;
    }

    public static FidoReturnValues VtIpReturnValues(FidoReturnValues lFidoReturnValues)
    {
      var queryVt = new VirusTotal(_vtKey);
      var ipReport = new List<IPReport>();

      foreach (var ip in lFidoReturnValues.DstIP)
      {
        ipReport.Add(queryVt.GetIPReport(ip));
      }

      lFidoReturnValues = CurrentDetector.GetCurrentDetector(lFidoReturnValues, ipReport);

      return lFidoReturnValues;
    }

    public static FidoReturnValues VtDomainReturnValues(FidoReturnValues lFidoReturnValues)
    {
      var queryVt = new VirusTotal(_vtKey);

      var domainReport = new List<DomainReport>();
      foreach (var domain in lFidoReturnValues.Domain)
      {
        domainReport.Add(queryVt.GetDomainReport(domain));
      }

      lFidoReturnValues = CurrentDetector.GetCurrentDetector(lFidoReturnValues, domainReport);

      return lFidoReturnValues;
    }

    public static FidoReturnValues TgReturnValues(FidoReturnValues lFidoReturnValues)
    {
      var tgRet = SendIOCToThreatGRID(lFidoReturnValues);
      lFidoReturnValues = CurrentDetector.GetCurrentDetector(lFidoReturnValues, tgRet);
      return lFidoReturnValues;
    }

    public static FidoReturnValues OdReturnValues(FidoReturnValues lFidoReturnValues)
    {
      var odRet = SendDomainIpToOpenDns(lFidoReturnValues.Domain, lFidoReturnValues.DstIP);
      lFidoReturnValues = CurrentDetector.GetCurrentDetector(lFidoReturnValues, odRet);
      return lFidoReturnValues;
    }

    private static ThreatGRIDReturnValues SendIOCToThreatGRID(FidoReturnValues lFidoReturnValues)
    {
      Console.WriteLine(@"Getting detailed information from ThreatGRID.");

      var artifact = new Dictionary<List<string>, ThreatArtifactEnum>();

      if (lFidoReturnValues.DstIP != null) artifact.Add(lFidoReturnValues.DstIP, ThreatArtifactEnum.Ip);
      if (lFidoReturnValues.Domain != null) artifact.Add(lFidoReturnValues.Domain, ThreatArtifactEnum.Domain);
      if (lFidoReturnValues.Url != null) artifact.Add(lFidoReturnValues.Url, ThreatArtifactEnum.Url);
      if (lFidoReturnValues.Hash != null) artifact.Add(lFidoReturnValues.Hash, ThreatArtifactEnum.Hash);

      var tgRet = ThreatGridQuery(artifact);
      
      return tgRet;
    }

    private static ThreatGRIDReturnValues ThreatGridQuery(Dictionary<List<string>, ThreatArtifactEnum> Artifact)
    {
      //todo: move this to the db
      short iDays = -180;
      var tgRet = new ThreatGRIDReturnValues();

      try
      {
        foreach (var artifact in Artifact)
        {
          foreach (var entry in artifact.Key)
          {

            var iocsearch = FeedsThreatGRID.SearchInfo(entry, artifact.Value, iDays);
            if (iocsearch == null) continue;
            tgRet.IPSearch = new List<ThreatGridSearchConfigClass.ThreatGRID_Search>() {iocsearch};
            if (tgRet.IPSearch == null) continue;
            if (!tgRet.IPSearch.Any()) continue;

            if (tgRet.IPSearch.Count > 0 && tgRet.IPSearch[0].Data.Items.Count > 0)
            {
              Console.WriteLine(@"Successfully found ThreatGRID hash data (" + tgRet.IPSearch.Count +
                                @" records)... storing in Fido.");

              if (tgRet.IPThreatInfo == null)
              {
                tgRet.IPThreatInfo = new List<ThreatGridThreatConfigClass.ThreatGridThreatInfo>();
              }

              for (var i = 0; i < tgRet.IPSearch.Count; i++)
              {
                for (var j = 0; j < tgRet.IPSearch[i].Data.Items.Count; j++)
                {
                  if (i >= 50 | j >= 50) continue;

                  if (string.IsNullOrEmpty(tgRet.IPSearch[i].Data.Items[j].HashID)) continue;
                  var x = FeedsThreatGRID.ThreatInfo(tgRet.IPSearch[i].Data.Items[j].HashID);
                  if (x == null) continue;
                  tgRet.IPThreatInfo.Add(x);
                }
              }
            }
          }
        }
        return tgRet;
      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error",
          "Fido Failed: {0} Exception caught in Threatfeed Hash area:" + e + " " + iDays + " " + tgRet.IPSearch.Count);
      }
      return tgRet;
    }

    private static OpenDNSClass SendDomainIpToOpenDns(List<string> Domain, List<string> DstIP)
    {
      var odReturn = new OpenDNSClass();
      var getFeed = new FeedsOpenDNS();

      if (DstIP != null)
      {
        odReturn.BgpRoutesIP = new List<BGPRoutesIP>();
        odReturn.DnsDbip = new List<DnsDBIP>();
        odReturn.LatestDomains = new List<LatestDomains>();

        foreach (var ip in DstIP)
        {
          odReturn.LatestDomains.AddRange(getFeed.GetLatestDomains(ip));
          odReturn.BgpRoutesIP.AddRange(getFeed.GetBGPRoutesIP(ip));
          odReturn.DnsDbip.Add(getFeed.GetDnsDbip(ip));
        }
      }

      if (odReturn.BgpRoutesIP.Any())
      {
        odReturn.BgpRoutesAsn = new List<BGPRoutesASN>();
        foreach (BGPRoutesIP t in odReturn.BgpRoutesIP.Where(t => !string.IsNullOrEmpty(t.asn.ToString())))
        {
          odReturn.BgpRoutesAsn.AddRange(getFeed.GetBGPRoutesASN(t.asn.ToString()));
        }
      }

      if (Domain == null)
      {
        Domain = new List<string>();
        foreach (var entry in odReturn.DnsDbip)
        {
          foreach (var record in entry.rrs)
          {
           if (!string.IsNullOrEmpty(record.rr)) Domain.Add(record.rr);
          }
        }
        //Domain.AddRange(odReturn.LatestDomains.Where(t => !string.IsNullOrEmpty(t.name)).Select(t => t.name));
        
      }

      if (Domain == null) return odReturn;

      odReturn.DomainStatus = new List<DomainStatus>();
      odReturn.DnsDBDomain = new List<DnsDBDomain>();
      odReturn.DomainsLatestTags = new List<DomainsLatestTags>();
      odReturn.DomainScore = new List<string>();
      odReturn.LinkedDomains = new List<LinkedDomains>();
      odReturn.SecurityScore = new List<SecurityScore>();
      odReturn.Whois = new List<Whois>();
      
      Console.WriteLine(@"Querying OpenDNS for information.");
      Parallel.ForEach(Domain.Take(10), domain =>
      //foreach (var domain in Domain)
      {
        if (domain == null) return;
        odReturn.DomainStatus.Add(getFeed.GetDomainStatus(domain));
        odReturn.DnsDBDomain.Add(getFeed.GetDnsDBDomain(domain));
        odReturn.DomainsLatestTags.AddRange(getFeed.GetDomainsLatestTags(domain));
        odReturn.DomainScore.Add(getFeed.GetDomainScore(domain));
        odReturn.LinkedDomains.Add(getFeed.GetLinkedDomains(domain));
        odReturn.SecurityScore.Add(getFeed.GetSecurityScore(domain));
        odReturn.Whois.AddRange(getFeed.GetWhois(domain));
      });


      return odReturn;
    }
  }
}