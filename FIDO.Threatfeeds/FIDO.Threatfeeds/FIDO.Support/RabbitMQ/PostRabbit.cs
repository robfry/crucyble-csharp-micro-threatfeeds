﻿using System;
using System.Text;
using FIDO.Threatfeeds.FIDO.Support.ErrorHandling;
using FIDO.Threatfeeds.FIDO.Support.Event.Queue;
using RabbitMQ.Client;

namespace FIDO.Threatfeeds.FIDO.Support.RabbitMQ
{
  public class PostRabbit
  {
    public void SendToRabbit(string strTimeDate, string uuid, string sExchange, string sQueue, string Host, EventQueueClass.PrimaryConfig EventQue)
    {
      var date = DateTime.UtcNow.ToString("s");
      var entry = "{ \"notification\": { \"eventtime\": \"" + strTimeDate + "\",\"currenttime\": \"" +
                   date + "\",\"uuid\": \"" + uuid + "\" }}";
      var newpost = new PostRabbit();
      newpost.Post(sExchange, sQueue, Host, entry, EventQue);
    }

    private void Post(string sExchange, string sRoutingKey, string sQueue, string hostname, string msgBody, EventQueueClass.PrimaryConfig eventQue)
    {
      var factory = new ConnectionFactory() { HostName = hostname };
      using (var connection = factory.CreateConnection())
      using (var channel = connection.CreateModel())
      {
        //channel.QueueDeclare(queue: sQueue,
        //                     durable: true,
        //                     exclusive: false,
        //                     autoDelete: false,
        //                     arguments: null);

        var body = Encoding.UTF8.GetBytes(msgBody);

        channel.BasicPublish(exchange: sExchange,
                             routingKey: sRoutingKey,
                             basicProperties: null,
                             body: body);
        Console.WriteLine(@"Message sent to: " + sExchange + @" " + sQueue);
        channel.Close();
        connection.Close();
      }

    }

    private void Post(string sExchange, string sQueue, string hostname, string msgBody, EventQueueClass.PrimaryConfig eventQue)
    {
      var factory = new ConnectionFactory() { HostName = hostname };
      try
      {
        using (var connection = factory.CreateConnection())
        {
          using (var channel = connection.CreateModel())
          {
            channel.ExchangeDeclare(exchange: sExchange,
                                    type: "fanout",
                                    durable: true,
                                    autoDelete: false,
                                    arguments: null
                                    );
            channel.QueueDeclare(queue: sQueue,
                                 durable: true,
                                 exclusive: false,
                                 autoDelete: false,
                                 arguments: null);

            var body = Encoding.UTF8.GetBytes(msgBody);

            channel.BasicPublish(exchange: sExchange,
              routingKey: string.Empty,
              basicProperties: null,
              body: body);
            Console.WriteLine(@"Message sent to: " + sExchange);
            channel.Close();
            connection.Close();
          }
        }
      }
      catch (Exception e)
      {
        FidoEventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught posting event to RabbitMQ:" + e);
      }
    }
  }
}
