package org.LL.arpAttack;

import java.util.Calendar;
import java.util.concurrent.TimeUnit;

import javax.swing.JOptionPane;

public class Timer extends Thread {
	long terminate_time;
	
	
	public Timer(int hour,int minute) {
		super();
		// TODO Auto-generated constructor stub
		Calendar c = Calendar.getInstance();
		c.set(c.get(Calendar.YEAR),
		c.get(Calendar.MONTH),
		c.get(Calendar.DATE), 
		hour, 	//hour
		minute);	//minute
		this.terminate_time = c.getTimeInMillis();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Runnable#run()
	 */
	public void run() {
		try {
			long cur_time = Calendar.getInstance().getTimeInMillis();
			long i = 0;
			
			//determine whether timeout once per 30 seconds
			while(System.currentTimeMillis() < this.terminate_time){
				//wait(1000);
				TimeUnit.SECONDS.sleep(30);
			}
		} catch (InterruptedException e) {
			e.printStackTrace();
		}finally{
			JOptionPane.showMessageDialog(null, " program stopped ");
			System.exit(0);
			
		}
	}
	
	
	
}
