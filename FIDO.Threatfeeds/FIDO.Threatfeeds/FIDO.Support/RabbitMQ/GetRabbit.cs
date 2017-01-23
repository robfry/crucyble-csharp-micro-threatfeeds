using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using FIDO.Threatfeeds.FIDO.Support.API.Endpoints;
using FIDO.Threatfeeds.FIDO.Support.ErrorHandling;
using FIDO.Threatfeeds.FIDO.Support.FidoDB;
using FIDO.Threatfeeds.FIDO.Support.Rest;
using FIDO.Threatfeeds.FIDO.Support.Threat.Feeds;
using Newtonsoft.Json;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using RabbitMQ.Client.MessagePatterns;

namespace FIDO.Threatfeeds.FIDO.Support.RabbitMQ
{
  public static class GetRabbit
  {
    public static void ReceiveNotificationQueue(string host, string exchange, string queue, ThreatFeedEnum enumType)
    {
      Console.WriteLine(@"Subscribing to : " + host + @" and queue: " + queue);
      var factory = new ConnectionFactory() { HostName = host };
      try
      {
        using (IConnection connection = factory.CreateConnection())
        {
          using (IModel channel = connection.CreateModel())
          {
            channel.ExchangeDeclare(exchange: exchange,
                                    durable: true,
                                    type: "fanout",
                                    autoDelete: false,
                                    arguments: null);

            channel.QueueDeclare(queue: queue,
                                 durable: true,
                                 exclusive: false,
                                 autoDelete: false,
                                 arguments: null);

            while (true)
            {
              var subscription = new Subscription(channel, queue, false);
              BasicDeliverEventArgs basicDeliveryEventArgs = subscription.Next();
              string messageContent = Encoding.UTF8.GetString(basicDeliveryEventArgs.Body);

              Console.WriteLine(messageContent);

              var rabbitmq = JsonConvert.DeserializeObject<RabbitMQClass.EventMsg>(messageContent);

              if (rabbitmq.notification.uuid == null) continue;

              var lFidoReturnValues = GetFidoJson(rabbitmq.notification.uuid);

              lFidoReturnValues = ReturnThreatfeedData(lFidoReturnValues, enumType);

              if (lFidoReturnValues == null) continue;
              var writeCouch = new FidoCouchDb();
              writeCouch.WriteToDBFactory(lFidoReturnValues);
              GC.Collect();

              if (lFidoReturnValues != null)
              {
                subscription.Ack(basicDeliveryEventArgs);
              }
            }
          }
        }
      }
      catch (Exception e)
      {
        Console.WriteLine(e.GetBaseException().Message);
        FidoEventHandler.SendEmail(e.GetBaseException().Message, "Fido Failed: {0} Exception caught retrieving messages from queue:" + e);
      }
    }

    private static FidoReturnValues ReturnThreatfeedData(FidoReturnValues lFidoReturnValues, ThreatFeedEnum enumType)
    {
      try
      {
        if (enumType == ThreatFeedEnum.Virustotal) lFidoReturnValues = ReturnVirusTotalThreatfeedData(lFidoReturnValues);
        if (enumType == ThreatFeedEnum.Threatgrid) lFidoReturnValues = ReturnThreatGridThreatfeedData(lFidoReturnValues);
        if (enumType == ThreatFeedEnum.Opendns) lFidoReturnValues = ReturnOpenDnsThreatfeedData(lFidoReturnValues);
        if (enumType == ThreatFeedEnum.Niddel) lFidoReturnValues = ReturnNiddelThreatfeedData(lFidoReturnValues);
        if (enumType == ThreatFeedEnum.Wildfire) lFidoReturnValues = ReturnWildfireThreatfeedData(lFidoReturnValues);
        if (enumType == ThreatFeedEnum.Seclytics) lFidoReturnValues = ReturnSeclyticsThreatfeedData(lFidoReturnValues);
        return lFidoReturnValues;
      }
      catch (Exception e)
      {
        Console.WriteLine(e.GetBaseException().Message);
        FidoEventHandler.SendEmail(e.GetBaseException().Message, "Fido Failed: {0} Exception caught retrieving messages from queue:" + e);
      }
      return null;
    }

    private static FidoReturnValues ReturnVirusTotalThreatfeedData(FidoReturnValues lFidoReturnValues)
    {
      if (lFidoReturnValues.Hash != null && lFidoReturnValues.Hash.Count > 0)
      {
        lFidoReturnValues = ThreatFeedsHash.VtHashReturnValues(lFidoReturnValues);
      }

      if (lFidoReturnValues.DstIP != null && lFidoReturnValues.DstIP.Count > 0)
      {
        lFidoReturnValues = ThreatFeedsNetwork.VtIpReturnValues(lFidoReturnValues);
      }

      if (lFidoReturnValues.Domain != null && lFidoReturnValues.Domain.Count > 0)
      {
        lFidoReturnValues = ThreatFeedsNetwork.VtDomainReturnValues(lFidoReturnValues);
      }

      if (lFidoReturnValues.Url != null && lFidoReturnValues.Url.Count > 0)
      {
        lFidoReturnValues = ThreatFeedsNetwork.VtUrlReturnValues(lFidoReturnValues);
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues ReturnThreatGridThreatfeedData(FidoReturnValues lFidoReturnValues)
    {
      try
      {
        lFidoReturnValues = ThreatFeedsNetwork.TgReturnValues(lFidoReturnValues);
        return lFidoReturnValues;
      }
      catch (Exception e)
      {
        Console.WriteLine(e.GetBaseException().Message);
        FidoEventHandler.SendEmail(e.GetBaseException().Message, "Fido Failed: {0} Exception caught retrieving messages from queue:" + e);
      }
      return null;
    }

    private static FidoReturnValues ReturnOpenDnsThreatfeedData(FidoReturnValues lFidoReturnValues)
    {
      lFidoReturnValues = ThreatFeedsNetwork.OdReturnValues(lFidoReturnValues);
      return lFidoReturnValues;
    }

    private static FidoReturnValues ReturnNiddelThreatfeedData(FidoReturnValues lFidoReturnValues)
    {
      return lFidoReturnValues;
    }

    private static FidoReturnValues ReturnWildfireThreatfeedData(FidoReturnValues lFidoReturnValues)
    {
      return lFidoReturnValues;
    }

    private static FidoReturnValues ReturnSeclyticsThreatfeedData(FidoReturnValues lFidoReturnValues)
    {
      return lFidoReturnValues;
    }

    private static FidoReturnValues GetFidoJson(string uuid)
    {

      //Load Fido configs from CouchDB
      var query = APIEndpoints.PrimaryConfig.host + APIEndpoints.PrimaryConfig.fido_events_alerts.dbname + @"/" + uuid;
      FidoReturnValues lFidoReturnValues;
      var connect = new RestConnection();

      try
      {
        var connection = (HttpWebRequest)WebRequest.Create(query);
        var stringreturn = connect.RestCall(connection);
        if (string.IsNullOrEmpty(stringreturn)) return null;
        lFidoReturnValues = JsonConvert.DeserializeObject<FidoReturnValues>(stringreturn);
        lFidoReturnValues.UUID = uuid;
        if (lFidoReturnValues == null)
        {
          Console.WriteLine(stringreturn);
        }
      }
      catch (Exception e)
      {
        Console.WriteLine(e.GetBaseException().Message);
        FidoEventHandler.SendEmail(e.GetBaseException().Message, "Fido Failed: {0} Exception caught in REST call to CouchDB to retrieve FIDO object:" + e);
        return null;
      }

      return lFidoReturnValues;
    }

    public class Value
    {
      public bool Detected { get; set; }
      public string Result { get; set; }
      public DateTime UpdateDate { get; set; }
      public string UpdateString { get; set; }
      public string Version { get; set; }
    }

    public class Scan
    {
      public string Key { get; set; }
      public Value Value { get; set; }
    }

    public class fubareport
    {
      public report[] report { get; set; }
    }

    public class report
    {
      public string MD5 { get; set; }
      public string Permalink { get; set; }
      public int Positives { get; set; }
      public string Resource { get; set; }
      public int ResponseCode { get; set; }
      public string SHA1 { get; set; }
      public string SHA256 { get; set; }
      public DateTime ScanDate { get; set; }
      public string ScanId { get; set; }
      public List<Scan> Scans { get; set; }
      public int Total { get; set; }
      public string VerboseMsg { get; set; }
    }

  }
}
