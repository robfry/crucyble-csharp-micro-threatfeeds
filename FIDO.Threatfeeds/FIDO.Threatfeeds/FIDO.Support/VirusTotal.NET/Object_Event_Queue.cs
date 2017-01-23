// Decompiled with JetBrains decompiler
// Type: FIDO_Detector.Fido_Support.Event_Queue.Object_Event_Queue
// Assembly: FIDO.Detector, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 1F8C2B1C-6416-497F-912F-E55767478E74
// Assembly location: D:\repository\repo\vs2015\Security\FIDO-Detector\FIDO-Detector\FIDO-Detector\bin\Debug\FIDO.Detector.exe

using System.Collections.Generic;

namespace FIDO.Threatfeeds.FIDO.Support.VirusTotal.NET
{
  public class Object_Event_Queue
  {
    public class Globalconfig
    {
      public string host { get; set; }

      public string port { get; set; }

      public bool ssl { get; set; }

      public bool auth { get; set; }

      public string id { get; set; }

      public string pwd { get; set; }

      public string key { get; set; }
    }

    public class Hostdetection
    {
      public Object_Event_Queue.Hostdetection.DDI ddi { get; set; }

      public Object_Event_Queue.Hostdetection.Whitelist whitelist { get; set; }

      public Object_Event_Queue.Hostdetection.GEOIP geoip { get; set; }

      public class DDI
      {
        public string exchange { get; set; }

        public string queue { get; set; }

        public string durability { get; set; }

        public bool autodelete { get; set; }

        public string messagettl { get; set; }

        public string autoexpire { get; set; }

        public string maxlength { get; set; }

        public string deadletterex { get; set; }

        public string deadletterrt { get; set; }

        public string arguments { get; set; }
      }

      public class Whitelist
      {
        public string exchange { get; set; }

        public string queue { get; set; }

        public string durability { get; set; }

        public bool autodelete { get; set; }

        public string messagettl { get; set; }

        public string autoexpire { get; set; }

        public string maxlength { get; set; }

        public string deadletterex { get; set; }

        public string deadletterrt { get; set; }

        public string arguments { get; set; }
      }

      public class GEOIP
      {
        public string exchange { get; set; }

        public string queue { get; set; }

        public string durability { get; set; }

        public bool autodelete { get; set; }

        public string messagettl { get; set; }

        public string autoexpire { get; set; }

        public string maxlength { get; set; }

        public string deadletterex { get; set; }

        public string deadletterrt { get; set; }

        public string arguments { get; set; }
      }
    }

    public class Notifications
    {
      public string exchange { get; set; }

      public string queue { get; set; }

      public string durability { get; set; }

      public bool autodelete { get; set; }

      public string messagettl { get; set; }

      public string autoexpire { get; set; }

      public string maxlength { get; set; }

      public string deadletterex { get; set; }

      public string deadletterrt { get; set; }

      public string arguments { get; set; }
    }

    public class Opendns
    {
      public string exchange { get; set; }

      public string queue { get; set; }

      public string durability { get; set; }

      public bool autodelete { get; set; }

      public string messagettl { get; set; }

      public string autoexpire { get; set; }

      public string maxlength { get; set; }

      public string deadletterex { get; set; }

      public string deadletterrt { get; set; }

      public string arguments { get; set; }
    }

    public class Threatgrid
    {
      public string exchange { get; set; }

      public string queue { get; set; }

      public string durability { get; set; }

      public bool autodelete { get; set; }

      public string messagettl { get; set; }

      public string autoexpire { get; set; }

      public string maxlength { get; set; }

      public string deadletterex { get; set; }

      public string deadletterrt { get; set; }

      public string arguments { get; set; }
    }

    public class Vt
    {
      public string exchange { get; set; }

      public string queue { get; set; }

      public string durability { get; set; }

      public bool autodelete { get; set; }

      public string messagettl { get; set; }

      public string autoexpire { get; set; }

      public string maxlength { get; set; }

      public string deadletterex { get; set; }

      public string deadletterrt { get; set; }

      public string arguments { get; set; }
    }

    public class Threatfeeds
    {
      public Object_Event_Queue.Opendns opendns { get; set; }

      public Object_Event_Queue.Threatgrid threatgrid { get; set; }

      public Object_Event_Queue.Vt vt { get; set; }
    }

    public class Production
    {
      public Object_Event_Queue.Globalconfig globalconfig { get; set; }

      public Object_Event_Queue.Hostdetection hostdetection { get; set; }

      public Object_Event_Queue.Notifications notifications { get; set; }

      public Object_Event_Queue.Threatfeeds threatfeeds { get; set; }
    }

    public class Test
    {
      public Object_Event_Queue.Globalconfig globalconfig { get; set; }

      public Object_Event_Queue.Hostdetection hostdetection { get; set; }

      public Object_Event_Queue.Notifications notifications { get; set; }

      public Object_Event_Queue.Threatfeeds threatfeeds { get; set; }
    }

    public class PrimaryConfig
    {
      public bool runtest { get; set; }

      public string host { get; set; }

      public Object_Event_Queue.Globalconfig globalconfig { get; set; }

      public Object_Event_Queue.Hostdetection hostdetection { get; set; }

      public Object_Event_Queue.Notifications notifications { get; set; }

      public Object_Event_Queue.Threatfeeds threatfeeds { get; set; }
    }

    public class Que
    {
      public bool runtest { get; set; }

      public Object_Event_Queue.PrimaryConfig production { get; set; }

      public Object_Event_Queue.PrimaryConfig test { get; set; }
    }

    public class Key
    {
      public string _id { get; set; }

      public string _rev { get; set; }

      public Object_Event_Queue.Que queues { get; set; }
    }

    public class Row
    {
      public string id { get; set; }

      public Object_Event_Queue.Key key { get; set; }

      public object value { get; set; }
    }

    public class Queues
    {
      public int total_rows { get; set; }

      public int offset { get; set; }

      public List<Object_Event_Queue.Row> rows { get; set; }
    }
  }
}
