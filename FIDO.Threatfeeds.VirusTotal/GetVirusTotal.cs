using System;
using FIDO.Threatfeeds.FIDO.Support.ErrorHandling;
using FIDO.Threatfeeds.FIDO.Support.Event.Queue;
using FIDO.Threatfeeds.FIDO.Support.FidoDB;
using FIDO.Threatfeeds.FIDO.Support.RabbitMQ;
using FIDO.Threatfeeds.FIDO.Support.Threat.Feeds;

namespace FIDO.Threatfeeds.VirusTotal
{
  internal static class GetVirusTotal
  {
    private static void Main(string[] args)
    {
      GetVirusTotalQueue();
    }

    private static void GetVirusTotalQueue()
    {
      try
      {
        while (true)
        {
          GetRabbit.ReceiveNotificationQueue(EventQueue.PrimaryConfig.host, EventQueue.PrimaryConfig.threatfeeds.vt.exchange, EventQueue.PrimaryConfig.threatfeeds.vt.queue, ThreatFeedEnum.Virustotal);
        }
      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught gathering rabbitmq events:" + e);
      }
    }
  }
}
