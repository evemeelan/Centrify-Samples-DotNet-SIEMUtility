using System;
using System.Collections.Generic;
using Centrify.Samples.DotNet.ApiLib;
using System.IO;
using System.Configuration;
using System.Collections;
using System.Web.Script.Serialization;

namespace Centrify.Samples.DotNet.SIEMUtility
{
    class SIEM_Utility
    {
        static string Version = "Version 1.0_8_22_16";

        static void Main(string[] args)
        {
            DateTime lastRunTime = DateTime.Now;

            if (File.Exists("LastRun.txt"))
            {
                lastRunTime = Convert.ToDateTime(File.ReadAllText("LastRun.txt"));
            }

            //Output all console logs to log file
            FileStream filestream = new FileStream("log.txt", FileMode.Create);
            var streamwriter = new StreamWriter(filestream);
            streamwriter.AutoFlush = true;
            Console.SetOut(streamwriter);
            Console.SetError(streamwriter);

            Console.WriteLine("Starting SIEM Utility... \n");
            Console.WriteLine("Application Version: " + Version);
            Console.WriteLine("Current System Time: " + DateTime.Now + Environment.NewLine);

            Console.WriteLine("Checking last run time and backing up files if needed...");

            if (lastRunTime < DateTime.Today)
            {
                var files = Directory.GetFiles(@".\Output\", "*.csv");
                string prefix = lastRunTime.Month.ToString() + "_" + lastRunTime.Day.ToString() + "_" + lastRunTime.Year.ToString() + "_";
                foreach (var file in files)
                {
                    string newFileName = Path.Combine(Path.GetDirectoryName(file), (prefix + Path.GetFileName(file)));
                    File.Move(file, newFileName);
                }
            }

            Console.WriteLine("Connecting to Centrify API...");

            //Authenticate to Centrify with no MFA service account
            RestClient authenticatedRestClient = InteractiveLogin.Authenticate(ConfigurationManager.AppSettings["CentrifyEndpointUrl"], ConfigurationManager.AppSettings["AdminUserName"], ConfigurationManager.AppSettings["AdminPassword"]);
            ApiClient apiClient = new ApiClient(authenticatedRestClient);

            Console.WriteLine("Getting list of queries...");

            //Read queries from query file
            JavaScriptSerializer m_jsSerializer = new JavaScriptSerializer();
            StreamReader jsonReader = new StreamReader("Queries.json");
            Dictionary<string, dynamic> queries_Dict = m_jsSerializer.Deserialize<Dictionary<string, dynamic>>(jsonReader.ReadToEnd());

            //Exicute queries in Queries file and export the results to ; delimeted CSV
            foreach (var query in queries_Dict["queries"])
            {
                Console.WriteLine("Exicuting Query {0}... \n", query["caption"]);
                ProcessQueryResults(query["caption"], apiClient.Query(query["query"]));
            }

            //Log last run time at every successful run.
            try
            {
                System.IO.File.WriteAllText(@".\LastRun.txt", DateTime.Now.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine("There Was An Error When Writing LastRun.txt");
                Console.WriteLine(ex.InnerException);
            }
        }

        static void ProcessQueryResults(string fileName, Dictionary<string, dynamic> results)
        {
            try
            {
                using (var writer = new StreamWriter(@"Output\" + fileName + ".csv"))
                {
                    //Add Columns to flat file based on the dictionary keys of the first result to ensure column and result order
                    int colCount = 1;
                    string columns = "";
                    List<string> keyList = new List<string>(results["Results"][0]["Row"].Keys);
                    foreach (var key in keyList)
                    {
                        if (keyList.Count == colCount)
                        {
                            columns = columns + key;
                        }
                        else
                        {
                            columns = columns + key + "; ";

                        }

                        colCount++;
                    }

                    writer.WriteLine(columns);
                    writer.Flush();

                    //Add each row to flat file                   
                    foreach (var result in results["Results"])
                    {
                        int pairCount = 1;
                        string row = "";

                        foreach (var pair in result["Row"])
                        {
                            if (result["Row"].Count == pairCount)
                            {
                                row = row + pair.Value;
                            }
                            else
                            {
                                row = row + pair.Value + "; ";

                            }

                            pairCount++;
                        }
                        writer.WriteLine(row);
                        writer.Flush();
                    }

                    Console.WriteLine("Query successfully written to CSV...");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("There was an error processing query to CSV: " + ex.InnerException);
            }
        }
    }
}
