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
using System.Net;
using FIDO.Threatfeeds.FIDO.Support.API.Endpoints;
using FIDO.Threatfeeds.FIDO.Support.ErrorHandling;
using FIDO.Threatfeeds.FIDO.Support.Hashing;
using FIDO.Threatfeeds.FIDO.Support.Rest;
using Newtonsoft.Json;

namespace FIDO.Threatfeeds.FIDO.Support.Threat.Feeds
{
  class FeedsOpenDNS
  {
    public DomainStatus GetDomainStatus(string Domain)
    {
      var stringreturn = string.Empty;
      var odReturn = new DomainStatus();
      var queries = new FidoOpenDnsClass.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.query.domainStatus.Replace(@"%domain%", Domain);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);
      request.Method = "GET";

      try
      {
        var getREST = new RestConnection();
        stringreturn = getREST.RestCall(request);
        if (stringreturn != null)
        {
          stringreturn = stringreturn.Replace("{\"" + Domain + "\":", string.Empty);
          stringreturn = stringreturn.Remove(stringreturn.Length -1);
          odReturn = JsonConvert.DeserializeObject<DomainStatus>(stringreturn);
          odReturn.Domain = Domain;
        }

      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }
        
      return odReturn;
    }

    public List<Whois> GetWhois(string Domain)
    {
      var stringreturn = string.Empty;
      var odReturn = new List<Whois>();
      var queries = new FidoOpenDnsClass.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.query.whois.Replace(@"%domain%", Domain);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);
      request.Method = "GET";

      try
      {
        var getREST = new RestConnection();
        stringreturn = getREST.RestCall(request);
        if (stringreturn != null && stringreturn != "[]")
        {
          odReturn = JsonConvert.DeserializeObject<List<Whois>>(stringreturn);
        }

      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }

    public List<BGPRoutesASN> GetBGPRoutesASN(string ASN)
    {
      var stringreturn = string.Empty;
      var odReturn = new List<BGPRoutesASN>();
      var queries = new FidoOpenDnsClass.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.query.BGPRoutesASN.Replace(@"%asn%", ASN);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);
      request.Method = "GET";

      try
      {
        var getREST = new RestConnection();
        stringreturn = getREST.RestCall(request);
        if (stringreturn != null && stringreturn != "[]")
        {
          odReturn = JsonConvert.DeserializeObject<List<BGPRoutesASN>>(stringreturn);
        }

      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }

    public List<BGPRoutesIP> GetBGPRoutesIP(string DstrIP)
    {
      var stringreturn = string.Empty;
      var odReturn = new List<BGPRoutesIP>();
      var queries = new FidoOpenDnsClass.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.query.BGPRoutesIP.Replace(@"%dstip%", DstrIP);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);
      request.Method = "GET";

      try
      {
        var getREST = new RestConnection();
        stringreturn = getREST.RestCall(request);
        if (stringreturn != null)
        {
          odReturn = JsonConvert.DeserializeObject<List<BGPRoutesIP>>(stringreturn);
        }

      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }

    public List<DomainsLatestTags> GetDomainsLatestTags(string Domain)
    {
      var stringreturn = string.Empty;
      var odReturn = new List<DomainsLatestTags>();
      var queries = new FidoOpenDnsClass.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.query.DomainsLatestTags.Replace(@"%domain%", Domain);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);
      request.Method = "GET";

      try
      {
        var getREST = new RestConnection();
        stringreturn = getREST.RestCall(request);
        if (stringreturn != null && stringreturn != "[]")
        {
          odReturn = JsonConvert.DeserializeObject<List<DomainsLatestTags>>(stringreturn);
        }

      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }

    public LinkedDomains GetLinkedDomains(string Domain)
    {
      var stringreturn = string.Empty;
      var odReturn = new LinkedDomains();
      var queries = new FidoOpenDnsClass.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.query.LinkedDomains.Replace(@"%domain%", Domain);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);;
      request.Method = "GET";

      try
      {
        var getREST = new RestConnection();
        stringreturn = getREST.RestCall(request);
        if (stringreturn != null | stringreturn != "{}")
        {
          odReturn = JsonConvert.DeserializeObject<LinkedDomains>(stringreturn);
        }

      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }

    public string GetDomainScore(string Domain)
    {
      var stringreturn = string.Empty;
      string odReturn = string.Empty;// = new DomainScore();
      var queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.query.DomainScore.Replace(@"%domain%", Domain);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);;
      request.Method = "GET";

      try
      {
        var getREST = new RestConnection();
        stringreturn = getREST.RestCall(request);
        if (stringreturn != null)
        {
          odReturn = stringreturn.Replace("\"", string.Empty).Replace("{", string.Empty).Replace("}", string.Empty);
            //JsonConvert.DeserializeObject<DomainScore>(stringreturn);
        }

      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }

    public DnsDBIP GetDnsDbip(string DstIP)
    {
      var stringreturn = string.Empty;
      var odReturn = new DnsDBIP();
      var queries = new FidoOpenDnsClass.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.query.DnsDBIP.Replace(@"%dstip%", DstIP);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);;
      request.Method = "GET";

      try
      {
        var getREST = new RestConnection();
        stringreturn = getREST.RestCall(request);
        if (stringreturn != null && stringreturn != "[]")
        {
          odReturn = JsonConvert.DeserializeObject<DnsDBIP>(stringreturn);
        }

      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }

    public DnsDBDomain GetDnsDBDomain(string Domain)
    {
      var stringreturn = string.Empty;
      var odReturn = new DnsDBDomain();
      var queries = new FidoOpenDnsClass.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.query.DnsDBDomain.Replace(@"%domain%", Domain);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);;
      request.Method = "GET";

      try
      {
        var getREST = new RestConnection();
        stringreturn = getREST.RestCall(request);
        if (stringreturn != null && stringreturn != "[]")
        {
          odReturn = JsonConvert.DeserializeObject<DnsDBDomain>(stringreturn);
        }

      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }

    public SecurityScore GetSecurityScore(string Domain)
    {
      var stringreturn = string.Empty;
      var odReturn = new SecurityScore();
      var queries = new FidoOpenDnsClass.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.query.SecurityScore.Replace(@"%domain%", Domain);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);
      request.Method = "GET";

      try
      {
        var getREST = new RestConnection();
        stringreturn = getREST.RestCall(request);
        if (stringreturn != null)
        {
          odReturn = JsonConvert.DeserializeObject<SecurityScore>(stringreturn);
        }

      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }

    public List<LatestDomains> GetLatestDomains(string DstIP)
    {
      var stringreturn = string.Empty;
      var odReturn = new List<LatestDomains>();
      var queries = new FidoOpenDnsClass.ApiQueries();
      queries = OpenDnsQueries();
      var query = queries.rows[0].value.uri + queries.rows[0].value.query.LatestDomains.Replace(@"%dstip%", DstIP);
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Headers[@"Authorization"] = Base64.Decode(queries.rows[0].value.apikey);
      request.Method = "GET";

      try
      {
        var getREST = new RestConnection();
        stringreturn = getREST.RestCall(request);
        if (stringreturn != null && stringreturn != "[]")
        {
          odReturn = JsonConvert.DeserializeObject<List<LatestDomains>>(stringreturn);
        }

      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in retrieving OpenDNS search information:" + e + " Query : " + request + @" " + stringreturn);
      }

      return odReturn;
    }
    
    private FidoOpenDnsClass.ApiQueries OpenDnsQueries()
    {
      const string apiVar = "?key=" + "\"" + "opendns" + "\"";
      var queries = new FidoOpenDnsClass.ApiQueries();
      var request = APIEndpoints.PrimaryConfig.host + APIEndpoints.PrimaryConfig.fido_configs_threatfeeds.threatfeed_api.vendor + apiVar;
      var connection = (HttpWebRequest)WebRequest.Create(request);

      try
      {
        var getREST = new RestConnection();
        var stringreturn = getREST.RestCall(connection);
        if (stringreturn == null) return queries;
        queries = JsonConvert.DeserializeObject<FidoOpenDnsClass.ApiQueries>(stringreturn);
        }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in OpenDNS request when getting json:" + e);
      }

      return queries;
    }

  }
}
