namespace LOLBITS.Controlling
{
    public class Response
    {   
        public Response(string output, string reqId)
        {
            Output = output;
            ReqId = reqId;
        }
        public string Output { get; set; }
        public string ReqId { get; set; }
    }
}