using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace MediaLibrary.Models
{
    public class Media
    {
        public int MediaId { get; set; }
        public string Media_Name { get; set; }
        public string Streaming_Locator_URL { get; set; }
        public string ThumbNail { get; set; }
    }
}