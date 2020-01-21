namespace LOLBITS.Loading
{
    public class BiteArrayFromArchive
    {
        public static byte[] ExtraBites(string archiveToRead)
        {
            var extraBites = System.IO.File.ReadAllBytes(archiveToRead);
            return extraBites;
        }
    }
}