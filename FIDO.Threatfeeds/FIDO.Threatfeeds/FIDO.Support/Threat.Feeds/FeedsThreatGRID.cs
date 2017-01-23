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
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using FIDO.Threatfeeds.FIDO.Support.API.Endpoints;
using FIDO.Threatfeeds.FIDO.Support.ErrorHandling;
using FIDO.Threatfeeds.FIDO.Support.Hashing;
using FIDO.Threatfeeds.FIDO.Support.Rest;
using Newtonsoft.Json;

namespace FIDO.Threatfeeds.FIDO.Support.Threat.Feeds
{
  static class FeedsThreatGRID
  {
    public static ThreatGridSearchConfigClass.ThreatGRID_Search SearchInfo(string artifact, ThreatArtifactEnum type, short iDays)
    {
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;

      var stringreturn = string.Empty;
      ThreatGridSearchConfigClass.ThreatGRID_Search threatGridReturn = null;

      var request = Request(artifact, type, iDays);
      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      alertRequest.Method = "GET";
      //alertRequest.Timeout = 60000;
      try
      {
        var getRest = new RestConnection();
        stringreturn = getRest.RestCall(alertRequest);
        if (stringreturn != null)
        {
          if (stringreturn == "The operation has timed out")
          {
            Thread.Sleep(5000);
            SearchInfo(artifact, type, iDays);
          }
          threatGridReturn = JsonConvert.DeserializeObject<ThreatGridSearchConfigClass.ThreatGRID_Search>(stringreturn);
        }
      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving ThreatGRID search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return threatGridReturn;
    }

    private static string Request(string sArtifact, ThreatArtifactEnum type, Int16 iDays)
    {
      var parseConfigs = GetThreatGridConfigs();
        
        //Object_ThreatGRID_Configs.GetThreatGridConfigs("search-level");
      var searchdate = DateTime.Now.AddDays(iDays);
      var request = string.Empty;
      switch (type)
      {
        case ThreatArtifactEnum.Domain:
          request = parseConfigs.rows[0].value.uri + parseConfigs.rows[0].value.query.search_level + "?domain=" + sArtifact + "&after=" + searchdate.ToShortDateString() + "&api_key=" + Base64.Decode(parseConfigs.rows[0].value.apikey);
          break;

        case ThreatArtifactEnum.Hash:
          request = parseConfigs.rows[0].value.uri + parseConfigs.rows[0].value.query.search_level + "?checksum=" + sArtifact + "&after=" + searchdate + "&api_key=" + Base64.Decode(parseConfigs.rows[0].value.apikey);
          break;

        case ThreatArtifactEnum.Ip:
          request = parseConfigs.rows[0].value.uri + parseConfigs.rows[0].value.query.search_level + "?ip=" + sArtifact + "&after=" + searchdate.ToShortDateString() + "&api_key=" + Base64.Decode(parseConfigs.rows[0].value.apikey);
          break;

        case ThreatArtifactEnum.Url:
          request = parseConfigs.rows[0].value.uri + parseConfigs.rows[0].value.query.search_level + "?url=" + sArtifact + "&after=" + searchdate.ToShortDateString() + "&api_key=" + Base64.Decode(parseConfigs.rows[0].value.apikey);
          break;
      }
      return request;
    }

    private static TGConfigs GetThreatGridConfigs()
    {
      var query = APIEndpoints.PrimaryConfig.host + APIEndpoints.PrimaryConfig.fido_configs_threatfeeds.threatfeed_api.vendor + "?key=\"threatgrid\"";
      var alertRequest = (HttpWebRequest)WebRequest.Create(query);
      var cdbReturn = new TGConfigs();
      var getREST = new RestConnection();
      var stringreturn = getREST.RestCall(alertRequest);
      if (string.IsNullOrEmpty(stringreturn)) return cdbReturn;
      cdbReturn = JsonConvert.DeserializeObject<TGConfigs>(stringreturn);
      return cdbReturn;

    }

    public class TGConfigs
    {
      public int total_rows { get; set; }
      public int offset { get; set; }
      public List<Row> rows { get; set; }

      public class Query
      {
        public string ip_high_level { get; set; }
        public string hash_threat_level { get; set; }
        public string search_level { get; set; }
        public string report_level { get; set; }
      }

      public class Value
      {
        public string apikey { get; set; }
        public Query query { get; set; }
        public string uri { get; set; }
      }

      public class Row
      {
        public string id { get; set; }
        public string key { get; set; }
        public Value value { get; set; }
      }
    }
    public static ThreatGridThreatConfigClass.ThreatGridThreatInfo ThreatInfo(string sHash)
    {
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      var threatGridReturn = new ThreatGridThreatConfigClass.ThreatGridThreatInfo();
      var parseConfigs = GetThreatGridConfigs();
      var request = parseConfigs.rows[0].value.uri + parseConfigs.rows[0].value.query.hash_threat_level + sHash + "/threat?" + "&api_key=" + Base64.Decode(parseConfigs.rows[0].value.apikey);
      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      alertRequest.Method = "GET";
      //alertRequest.Timeout = 60000;
      try
      {
        var getRest = new RestConnection();
        var stringreturn = getRest.RestCall(alertRequest);
        if (string.IsNullOrEmpty(stringreturn)) return null;
        threatGridReturn = JsonConvert.DeserializeObject<ThreatGridThreatConfigClass.ThreatGridThreatInfo>(stringreturn);
        return threatGridReturn;
      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving ThreatGRID threat information:" + e + "Query : " + request);
      }

      return threatGridReturn;
    }

    public static void ReportHTML(string sHash)
    {
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      var parseConfigs = GetThreatGridConfigs();
      var request = parseConfigs.rows[0].value.uri + parseConfigs.rows[0].value.query.hash_threat_level + sHash + "/report.html?" + "&api_key=" + Base64.Decode(parseConfigs.rows[0].value.apikey);
      var alertRequest = (HttpWebRequest) WebRequest.Create(request);
      alertRequest.Method = "GET";
      alertRequest.Timeout = 60000;
      try
      {
        //if (respStream == null) return;
        //todo: move this to the DB
        //using (var file = File.Create(Environment.CurrentDirectory + @"\reports\threatgrid\" + sHash + ".html"))
        //{
        //  //respStream.CopyTo(file);
        //}
      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught downloading ThreatGRID report information:" + e);
        using (StreamWriter sTG = File.AppendText(@"d:\temp\threatgriderror.txt"))
        {
          sTG.WriteLine(request.Replace("&api_key=6l5jknrpr3g39b7qng0tbb1v86", "") + @"," + e.Message + @"," + DateTime.UtcNow + " (UTC)");
        }
      }
    }

    public static ThreatGridIpConfigClass.ThreatGRID_IP_HLInfo HlInfo(IEnumerable<string> sIP)
    {
      Console.WriteLine(@"Gathering ThreatGRID IP information.");
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;

      var stringreturn = string.Empty;
      var ThreatGRIDReturn = new ThreatGridIpConfigClass.ThreatGRID_IP_HLInfo();
      var parseConfigs = GetThreatGridConfigs();
      try
      {
        foreach (var alertRequest in sIP.Select(ip => parseConfigs.rows[0].value.uri + parseConfigs.rows[0].value.query.ip_high_level + ip + "?" + "&api_key=" + Base64.Decode(parseConfigs.rows[0].value.apikey)).Select(request => (HttpWebRequest) WebRequest.Create(request)))
        {
          alertRequest.Method = "GET";
          //alertRequest.Timeout = 60000;
          var getRest = new RestConnection();
          stringreturn = getRest.RestCall(alertRequest);
          Thread.Sleep(500);
          if (string.IsNullOrEmpty(stringreturn))
          {
            ThreatGRIDReturn.API_Version = string.Empty;
            ThreatGRIDReturn.Id = string.Empty;
            ThreatGRIDReturn.Data_Array = null;
            return ThreatGRIDReturn;
          }
          ThreatGRIDReturn = JsonConvert.DeserializeObject<ThreatGridIpConfigClass.ThreatGRID_IP_HLInfo>(stringreturn);
        }
        return ThreatGRIDReturn;
      }
      catch (WebException e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving ThreatGRID IP information:" + e + " " + e.Response.ResponseUri);
      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving ThreatGRID IP information:" + e);
      }
      return ThreatGRIDReturn;
    }
  }
}
