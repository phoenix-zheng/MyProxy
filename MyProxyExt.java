
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.Vector;
import java.util.concurrent.ArrayBlockingQueue;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class MyProxyExt {

	private static final String PROXY_LIST_URL = "https://www.proxy-list.download/api/v1/get?type=http";
	private static final String TEST_URL = "https://www.google.com";
	private static final String ALL_IPS_FILE_NAME = "ip.txt";
	private static final String VALID_IPS_FILE_NAME = "good.txt";
	private static final String END_STRING = "End";
	private static final String PROXY_FOR_CAPTURE = null;//"127.0.0.1:8080";
	private static final int STEP1_CHECK_TIMES = 5;
	private static final int STEP2_CHECK_TIMES = 10;
	private static final int QUE_SIZE = 20;
	private static final int TASK_NUM = 500;
	private static final int CONNECTION_TIMEOUT = 10000;
	private static final int READ_TIMEOUT = 20000;
	
	private String TAG = this.getClass().getName();	

	private boolean mFromServer;
	private Vector<String> mResult;
	private List<String> mProxyList;
	private RankIps mRank;
	private long mStart;
	enum DebugLevel {
		ERROR, WARINING, INFOR, DEBUG, VERBOSE
	}
	private DebugLevel DBG = DebugLevel.DEBUG;
	
	enum ConnectionType{		
		HTTP, HTTPS
	}
		
	public static void main(String[] args)  {
		MyProxyExt instance = new MyProxyExt();
		instance.rankValidIps();
	}
	public MyProxyExt() {
		// TODO Auto-generated constructor stub
		mFromServer = true;
		mResult = new Vector<String>();
		mProxyList = new ArrayList<String>();
		mRank = new RankIps();
		mStart = System.currentTimeMillis();
	}
	
	private void logv(String tag, String log) {
		long end = System.currentTimeMillis();
		if (DBG.compareTo(DebugLevel.VERBOSE) >= 0) {
			System.out.println("[" + (end-mStart) + "]" + "V[" + tag + "]" + log);
		}
	}

	private void logd(String tag, String log) {
		long end = System.currentTimeMillis();
		if (DBG.compareTo(DebugLevel.DEBUG) >= 0) {
			System.out.println("[" + (end-mStart) + "]" + "D[" + tag + "]" + log);
		}
	}

	private void logi(String tag, String log) {
		long end = System.currentTimeMillis();
		if (DBG.compareTo(DebugLevel.INFOR) >= 0) {
			System.out.println("[" + (end-mStart) + "]" + "I[" + tag + "]" + log);
		}
	}

	private void loge(String tag, String log) {
		long end = System.currentTimeMillis();
		if (DBG.compareTo(DebugLevel.ERROR) >= 0) {
			System.out.println("[" + (end-mStart) + "]" +  "E[" + tag + "]" + log);
		}
	}

	private void rankValidIps() {
		getValidIps();
		clearRank();
		rankIps();
		showResult();
	}

	private void getValidIps() {
		checkProxyList(false);		
	}

	private void clearRank() {
		mRank.clear();
	}

	private void rankIps() {
		checkProxyList(true);		
	}

	private void showResult() {
		mRank.showResult();
	}
	
	private void checkProxyList(boolean doRank) {
		ArrayBlockingQueue<String> queOrigin = new ArrayBlockingQueue<String>(QUE_SIZE);
		ArrayBlockingQueue<String> queResullt = new ArrayBlockingQueue<String>(QUE_SIZE);
		
		long start = System.currentTimeMillis();
		getProxyList(doRank);
		
		logv(TAG, "Create tasks");
		Thread getIpsTask = new Thread(new GetIpsTask(queOrigin));
		getIpsTask.start();
		int taskNum = TASK_NUM;
		if (doRank) {
			if (mResult.size() < TASK_NUM) {
				taskNum = mResult.size();
			}
		} else {
			if (mProxyList.size() <TASK_NUM) {
				taskNum = mProxyList.size();
			}
		}
		logd(TAG, "Create " + taskNum + " tasks to check ip");
		Thread checkIpTask[] = new Thread[taskNum];
		for (int i = 0; i < taskNum; i++) {
			logv(TAG, "Create thread " + (i+1) + " to check ip");
			checkIpTask[i] = new Thread(new CheckIpTask(queOrigin, queResullt,	 i));
			checkIpTask[i].start();
		}
		Thread saveResultThread = null;	
		saveResultThread = new Thread(new SaveResultTask(queResullt));
		saveResultThread.start();
	
		try {
			getIpsTask.join();
			logd(TAG, "get ip finished");
		} catch (InterruptedException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		for (int i = 0; i < taskNum; i++) {
			try {
				checkIpTask[i].join();
				logd(TAG, "check ip task" + i + " finished");
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		logd(TAG, "Notify saveResultThread to finish");
		try {
			queResullt.put(END_STRING);
		} catch (InterruptedException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		try {
			saveResultThread.join();
			logd(TAG, "Save result thread finished");
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
		logd(TAG, "result " + mResult);
	}

	private void getProxyList(boolean doRank) {
		mProxyList.clear();
		List<String>list = new ArrayList<String>();
		if (doRank) {
			list = mResult;
		} else if (mFromServer) {
			logd(TAG, "get proxy list from server");
			list = readDataFromWebServer(PROXY_LIST_URL, PROXY_FOR_CAPTURE);
			
		} else {
			try {
				logd(TAG, "get proxy list from file");
				list = Files.readAllLines(FileSystems.getDefault().getPath(System.getProperty("user.dir"), VALID_IPS_FILE_NAME));
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return;
			}
		}
		if (list == null || list.size() <= 0) {
			loge(TAG, "Get proxy list failed");
			return;
		}
		int times = STEP1_CHECK_TIMES;
		if (doRank) {
			times = STEP2_CHECK_TIMES;
		} else {
			mRank.setTotalIpNumber(list.size());
		}
		
		for (int i=0; i<times; i++) {
			if (list != null) {
				mProxyList.addAll(list);
			}
		}
		return;
	}
	   
	class GetIpsTask implements Runnable {
		public GetIpsTask(ArrayBlockingQueue<String> que) {
			this.que = que;
		}
		public void run() {
			logv(TAG, "run");
			for (String line : mProxyList) {
				try {
					logd(TAG, "que put " + line);
					que.put(line);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					return;
				}
			}
			logd(TAG, "put end string");
			try {
				que.put(END_STRING);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}	
		}
		private ArrayBlockingQueue<String> que;
		private String TAG = this.getClass().getName();
	}
	
	class CheckIpTask implements Runnable{
		
		public CheckIpTask(ArrayBlockingQueue<String> queIn, ArrayBlockingQueue<String>queOut, int id) {
			// TODO Auto-generated constructor stub
			this.queIn = queIn;
			this.queOut = queOut;
			this.TAG = this.getClass().getName() + id; 
		}
		
		public void run() {
			logv(TAG, "run");

			String ip = null;
			while (true) {
				logd(TAG, "wait que to take...");				
				try {
					ip = queIn.take();
					if (END_STRING.equals(ip)) {
						break;
					}
				} catch (InterruptedException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
					return;
				}
				long start, end;
				start = System.currentTimeMillis();
				logv(TAG, "Check ip " + ip);
				if (checkIp(ip)) {
					end = System.currentTimeMillis();
					mRank.add(ip, end-start);
					try {
						queOut.put(ip);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
						return;
					}	
				} else {
					end = System.currentTimeMillis();
					if (mRank.isIpAdded(ip)) {
						mRank.add(ip, CONNECTION_TIMEOUT);
					}
				}
				logv(TAG, "This ip cost " + (end - start) + " ms");
			}
			try {
				logd(TAG, "Put end string back to notify other thread");
				queIn.put(END_STRING);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		private boolean checkIp(String ip) {
			return readDataFromWebServer(TEST_URL, ip) != null;			
		}

		private ArrayBlockingQueue<String> queIn, queOut;
		private String TAG = null;
	}
	
	class SaveResultTask implements Runnable{

		public SaveResultTask(ArrayBlockingQueue<String>que) {
			// TODO Auto-generated constructor stub
			this.que = que;
		}
		
		public void run() {
			PrintWriter pw = null;
			try {
				String resultFile = System.getProperty("user.dir") + "\\" + VALID_IPS_FILE_NAME;
				logd(TAG, "result file " + resultFile);
				pw = new PrintWriter(resultFile);
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return;
			}

			String ip = null;
			HashSet<String> set = new HashSet<String>();
			while(true) {
				try {
					ip = que.take();
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				if (END_STRING.equals(ip)) {
					logd(TAG, "Get end string, quit");
					break;
				}
				set.add(ip);
			}
			for (String _ip : set) {
				logd(TAG, "save ip " + _ip);
				saveResult(pw, _ip);
			}
		}
		private  boolean saveResult(PrintWriter pw, String ip) {
			if (pw == null) {
				loge(TAG, "invalid PrintWriter");
				return false;
			}
			pw.println(ip);
			pw.flush();
			mResult.add(ip);
			return true;
		}
		private ArrayBlockingQueue<String> que;
		private String TAG = this.getClass().getName();
	}

	private List<String> readDataFromWebServer(String url, String ip) {
		Proxy proxy = null;
		ConnectionType type;
		logd(TAG, "readDataFromWebServer, url:" + url + " ip: " + ip);
		if (ip != null) {
			String address = ip.substring(0, ip.indexOf(':'));
			String port = ip.substring(ip.indexOf(':') + 1);
			logd(TAG, "Check proxy address " + address + " port " + port);
			proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(address, Integer.valueOf(port)));  // 实例化本地代理对象，端口为8888
		}
		if (url.startsWith("http:")) {
			type = ConnectionType.HTTP;
			return readDataByHttp(url, proxy);
		} else if (url.startsWith("https:")) {
			type = ConnectionType.HTTPS;
			return readDataByHttps(url, proxy);
		} else {
			loge(TAG, "Invalid http type");
			return null;
		}
		/*
		logd(TAG, "type " + type);
		switch (type) {
			case HTTP:
				return readDataByHttp(url, proxy);
			
			case HTTPS:
				return readDataByHttps(url, proxy);
			
			default:
				return null;
		}*/
	}
	private List<String> readDataByHttp(String url, Proxy proxy) {
		URL u;
		try {
			u = new URL(url);
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

		HttpURLConnection connection;
		logd(TAG, "Open url " + url);
		try {
			if (proxy != null) {
				connection = (HttpURLConnection)u.openConnection(proxy);
			} else {
				connection = (HttpURLConnection)u.openConnection();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			loge(TAG, "Open connection failed");
			return null;
		} 
		connection.setConnectTimeout(CONNECTION_TIMEOUT);
		connection.setReadTimeout(READ_TIMEOUT);
		InputStream in;
		logv(TAG, "getInputStream");
		try {
			in = connection.getInputStream();
		} catch (java.net.ConnectException e) {
			// TODO Auto-generated catch block
			loge(TAG, "Connect timeout");			
			return null;
		} catch (java.net.SocketException e) {
			loge(TAG, "Connection reset");
			return null;
		} catch (java.net.SocketTimeoutException e) {
			loge(TAG, "Socket timeout");
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}

	    try {
			if (connection.getResponseCode() == 200) {
				logd(TAG, "Response success");
			} else {
				loge(TAG, "Error response");
				return null;
			}
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return null;
		}
		BufferedReader br;
		try {
			br = new BufferedReader(new InputStreamReader(in,"UTF-8"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

		StringBuilder sb = new StringBuilder();

		String lin = System.getProperty("line.separator") ;
		logv(TAG, "readline");
		List<String> result = new ArrayList<String>();
		try {
			for(String temp = br.readLine() ; temp!=null;temp = br.readLine() ){	
				sb.append(temp+lin);
				result.add(temp);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

		try {
			br.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		try {
			in.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		logd(TAG, sb.toString());
		return result;
	}

	private List<String> readDataByHttps(String url, Proxy proxy) {
	    SSLContext sc = null;
		try {
			sc = createSslContext();
		} catch (KeyManagementException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		
	    HttpsURLConnection conn = null;
		try {
			if (proxy != null) {
				conn = (HttpsURLConnection) new URL(url).openConnection(proxy);
			} else {
				conn = (HttpsURLConnection) new URL(url).openConnection();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	    conn.setSSLSocketFactory(sc.getSocketFactory());
	    conn.setHostnameVerifier((s, sslSession) -> true);
	    try {
			conn.setRequestMethod("GET");
		} catch (ProtocolException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return null;
		}
	    conn.setConnectTimeout(CONNECTION_TIMEOUT);
	    conn.setReadTimeout(READ_TIMEOUT);
	    conn.setDoInput(true);
	    conn.setDoOutput(true);
	    conn.setRequestProperty("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36");
	    /*try {
			OutputStreamWriter out = new OutputStreamWriter(conn.getOutputStream(), "UTF-8");
			out.write("type=http");
			out.flush();
			out.close();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}*/
	    
	    /*
	    try {
			conn.connect();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}*/
	    try {
			if (conn.getResponseCode() == 200) {
				logd(TAG, "Response success");
			} else {
				loge(TAG, "Error response");
				return null;
			}
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			loge(TAG, "Connection reset");
			return null;
		} catch (SocketTimeoutException e) {
			// TODO Auto-generated catch block
			loge(TAG, "Socket timeout");
			return null;
		}  catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return null;
		}
	    
	    List<String> result = new ArrayList<String>();
	    try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
	        String line;
	        while (null != (line = br.readLine())) {
	        result.add(line);
	        }
	    } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	    conn.disconnect();
	    return result;
	}
	
	private List<String> getProxyListFromServer(String url, String ip) {
		logd(TAG, "getProxyListFromServer from " + url);
	    //logd(TAG, "mProxyList: " + mProxyList);
	    return readDataFromWebServer(url, ip);
	}
	
    private static SSLContext createSslContext() throws NoSuchAlgorithmException, KeyManagementException {
        //SSLContext sc = SSLContext.getInstance("SSL");
    	SSLContext sc = SSLContext.getInstance("TLSv1.2");
    	
        sc.init(null, new TrustManager[]{new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }}, new java.security.SecureRandom());

        return sc;
    }
 	
	class RankIps {
		private final String TAG = this.getClass().getName();
		private HashMap<String, TreeSet<Long>> mRankMap = new HashMap<String, TreeSet<Long>>();
		private int mTotalIpsNum;
		
		public synchronized void add(String ip, long time) {
			logd(TAG, "add " + ip + " cost " + time + "ms");
			TreeSet<Long> tree = mRankMap.get(ip); 
			if (tree == null) {
				logd(TAG, "Create TreeSet for " + ip);
				tree = new TreeSet<Long>();
				tree.add(Long.valueOf(time));
				mRankMap.put(ip, tree);	
			} else {
				tree.add(Long.valueOf(time));
			}
		}
		
		public boolean isIpAdded(String ip) {
			return mRankMap.get(ip) != null;
		}
		
		private long getBestTime(String ip) {
			if (mRankMap.get(ip) != null) {
				return mRankMap.get(ip).first().longValue();
			} else {
				return Long.MAX_VALUE;
			}			
		}
		
		private long getAverageTime(String ip) {
			if (mRankMap.get(ip) != null) {
				long sum = 0;
				long size = 0;
				for (Long time : mRankMap.get(ip)) {
					sum = sum +time.longValue();
					size ++;
				}
				return sum/size;
			} else {
				return Long.MAX_VALUE;
			}			
		}

		public synchronized TreeMap<Long, String> getBestMinTime() {
			TreeMap<Long, String> bests = new TreeMap<Long, String>();
			for (String ip : mRankMap.keySet()) {
				logd(TAG, "put min time " + getBestTime(ip) + " for ip "+ ip);
				bests.put(getBestTime(ip), ip);
			}
			return bests;
		}
		
		public synchronized TreeMap<Long, String> getBestAverageTime() {
			TreeMap<Long, String> bests = new TreeMap<Long, String>();
			for (String ip : mRankMap.keySet()) {
				logd(TAG, "put average time " + getAverageTime(ip) + " for ip "+ ip);
				bests.put(getAverageTime(ip), ip);
			}
			return bests;
		}
		public synchronized void clear() {
			mRankMap.clear();
		}
		public void setTotalIpNumber(int num) {
			mTotalIpsNum = num;
		}
		public int getTotalIpNumber() {
			return mTotalIpsNum;
		}
	
		public synchronized void showBestMinTimeResult() {
			logi(TAG, "Best min time:");	
			TreeMap<Long, String> tree = getBestMinTime();
			int i = 1;
			for (Entry<Long, String> entry : tree.entrySet()) {
				logi(TAG, i + ". ip:" + entry.getValue() + " Min time:" + entry.getKey() + " ms");		
				i++;
			}
		}

		private int getCountForSuccess(String ip) {
			return mRankMap.get(ip).size();
		}
		public synchronized void showBestAverageTimeResult() {
			logi(TAG, "Best average time:");
			TreeMap<Long, String> tree = getBestAverageTime();
			int i = 1;
			for (Entry<Long, String> entry : tree.entrySet()) {
				logi(TAG, i + ". ip: " + entry.getValue() + " Average time:" + entry.getKey() + " ms "
						+  getCountForSuccess(entry.getValue()) +  " success in " + STEP2_CHECK_TIMES);	
				i++;
			}
		}

		public synchronized void showResult() {
			logi(TAG, "Total ips number " + getTotalIpNumber());
			showBestMinTimeResult();
			showBestAverageTimeResult();
		}
	}
}

