/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package btc;

import core.*;
import input.RumusMatematika;
import java.security.PublicKey;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;

/**
 *
 * @author WINDOWS_X
 */
public class Incentive {

    private static boolean blacklistActive = false;

    private static Map<Message, List<DTNHost>> ack = new HashMap<Message, List<DTNHost>>();
    private static Map<String, Tuple<Transaction, Boolean>> deposits = new HashMap<String, Tuple<Transaction, Boolean>>();
    private static Map<Message, Map<DTNHost, Set<String>>> verificating = new HashMap<Message, Map<DTNHost, Set<String>>>(); //verificating isinya pesan, dibawa host ini sama verficatornya
    private static Map<String, Set<DTNHost>> trustToken = new HashMap<String, Set<DTNHost>>();
    private static Map<Message, Set<String>> pending = new HashMap<Message, Set<String>>(); //sek wes disetujui tapi belum lengkap
    private static Set<Message> finished = new HashSet<Message>(); //
    private static Map<String, Tuple<Double, Double>> time = new HashMap<String, Tuple<Double, Double>>();

    private static Set<DTNHost> blacklist = new HashSet<DTNHost>();
    private static int jumlahVerificator =1;
    private static int transaksiok = 0;
    private static int transaksigagal = 0;

    public static void setAck(Message m, Map<DTNHost, PublicKey> publicKeys) {
        int in = 0;
        //baca node yang dilewati pesan
        List<DTNHost> nodes = m.getHops();
        //ambil signatures yang diberikan di pesan
        List<byte[]> signatures = (List<byte[]>) m.getProperty("signatures");
        //membuat list untuk menampung host yang sudah diverifikasi
        List<DTNHost> verified = new ArrayList<DTNHost>();

        //membaca semua host di dalam nodes (node yang dilewati pesan)
        for (DTNHost host : nodes) {
            //mengecualikan node pertama (pembuat pesan) dan node terakhir (tujuan)
            if (in > 0 && (in < nodes.size() - 1)) {

                /*
                jika wallet dari node yang dilewati sesuai dengan
                wallet yang dicatat di pesan maka wallet dicatat
                ke dalam verified list
                 */
                String validation = m.toString() + host.toString();

                try {
                    String signature = do_RSADecryption(signatures.get(in), publicKeys.get(host));

                    if (signature.matches(validation)) {
                        verified.add(host);
                    } else {
                        if (blacklistActive) {
                            blacklist.add(host);
                        }
                    }
                } catch (Exception ex) {
                    if (blacklistActive) {
                        blacklist.add(host);
                    }
                }
            }
            //index naik untuk membaca isi list wallet dari awal hingga akhir
            in++;
        }

        time.put(m.toString(), new Tuple(SimClock.getTime(), -1.0));
        ack.put(m, verified);
    }

    public static void setTrustToken(DTNHost host, Set<Message> messages, boolean status, DTNHost verificator) {

        //membaca pesan dari List messages
        for (Message message : messages) {
            //baca ack
            for (Map.Entry<Message, List<DTNHost>> entry : ack.entrySet()) {
                //baca pesan di ack
                Message m = entry.getKey();
                //baca host di ack
                List<DTNHost> hosts = entry.getValue();
                //jika pesan dalam ack sama dengan pesan yang di trust token
                //to string ksarena objek yang dibawa trust token sama di ack beda, karena properti tanda tangannya
                if (m.toString().matches(message.toString())) {
                    //jika host di ack mengandung host yang sedang mengirim trustoken
                    if (hosts.contains(host)) {
                        
                        //buat list verivicators
                        Set<String> verificators;
                        //buat map tup isinya dtn host sama list string
                        Map<DTNHost, Set<String>> tup;
                        //jika verificating mengandung pesan di ack
                        if (verificating.containsKey(m)) {
                            tup = verificating.get(m);
                            if (tup.containsKey(host)) {
                                verificators = tup.get(host);
                            } else {
                                verificators = new HashSet<String>();
                            }
                        } else { //jika tidak ada 
                            //isi buat map tup isinya dtn host dan string
                            tup = new HashMap<DTNHost, Set<String>>();
                            //HashSet buat verificator
                            verificators = new HashSet<String>();
                        }

                        int counterOkay = 0;
                        int counterFailed = 0;
                       
                        for (String counting : verificators) {
                            if (counting.startsWith("+")) {
                                counterOkay++;
                            }
                            if (counting.startsWith("-")) {
                                counterFailed++;
                            }
                        }
                       
                        if(!(counterOkay>=jumlahVerificator || counterFailed>=jumlahVerificator)){
                            String okay = "+" + verificator;
                            String failed = "-" + verificator;

                            if (!(verificators.contains(okay) || verificators.contains(failed))) {
                                if (status) {
                                    verificators.add(okay);
                                } else {
                                    verificators.add(failed);
                                }
                            }

                            tup.put(host, verificators);
                            verificating.put(m, tup);
                        }
                       
//                        System.out.println("verificating");
//                        System.out.println(verificating);
                    }
                }
            }
        }
    }

    public static void createIncentive() {
        for (Map.Entry<Message, Map<DTNHost, Set<String>>> entry : verificating.entrySet()) { //nunggu verifikasi
            Message message = entry.getKey();
            Map<DTNHost, Set<String>> value1 = entry.getValue();

            for (Map.Entry<DTNHost, Set<String>> entry2 : value1.entrySet()) {
                DTNHost host = entry2.getKey();
                Set<String> verificators = entry2.getValue();

                int counterOk = 0;
                int counterFail = 0;

                for (String verificator : verificators) {
                    if (verificator.startsWith("+")) {
                        counterOk++;

                    }
                    if (verificator.startsWith("-")) {
                        counterFail++;

                    }
                }

                if (!((verificators.size() >= jumlahVerificator) && (counterOk >= jumlahVerificator || counterFail >= jumlahVerificator))) {
                    break;
                } else {
                    if (!finished.contains(message)) {
                        Set<String> hasil;

                        if (pending.containsKey(message)) {
                            hasil = pending.get(message);
                        } else {
                            hasil = new HashSet<String>();
                        }

                        String fail = "-" + host;
                        String ok = "+" + host;

                        if (!(hasil.contains(ok) || hasil.contains(fail))) {
                            if (counterOk >= jumlahVerificator) {
                                hasil.add(ok);
                            }
                            if (counterFail >= jumlahVerificator) {
                                hasil.add(fail);
                                if(blacklistActive){
                                blacklist.add(host);
                                }
                            }
                        }
                        pending.put(message, hasil);
                    }
                }
//                System.out.println("pending");
//                System.out.println(pending);
            }

        }

        if (!pending.isEmpty()) {
//            System.out.println("finished : " + finished);
            prosesPayment();

//            System.out.println("blacklist : " + blacklist);
        }
    }

    public static void prosesPayment() {
        Set<Message> toBeDel = new HashSet<Message>();
        for (Map.Entry<Message, Set<String>> entry : pending.entrySet()) {
            Message m = entry.getKey();
            if (!(finished.contains(m))) {
                if (ack.get(m).size() == pending.get(m).size()) {
                    if (deposits.containsKey(m.toString())) {
                        Tuple<Transaction, Boolean> tup = deposits.get(m.toString());
                        float rewards = (float) m.getProperty("rewards");
                        if (!tup.getValue()) {
                            BlockChain.addTransaction(m.getFrom().getWallet().sendFunds(m.getTo().getWallet().publicKey, rewards));
                            Tuple<Transaction, Boolean> newTup = new Tuple<Transaction, Boolean>(tup.getKey(), true);
                            deposits.put(m.toString(), newTup);
                        }

                        List<DTNHost> hosts = ack.get(m);
                        List<DTNHost> pay = new ArrayList<DTNHost>();

                        for (DTNHost d : hosts) {
                            String ok = "+" + d;
                            if (pending.get(m).contains(ok)) {
                                pay.add(d);
                                if (d.toString().startsWith("Mis")) {
                                    transaksiok++;
                                }
                            } else {
                                if ((d.toString().startsWith("Mis"))) {
                                    transaksigagal++;
                                }
                            }
                        }

                        float amount = rewards / pay.size();

                        float updateamount = rewards;
                        int indx = 0;

                        for (DTNHost p : pay) {
                            if (indx < pay.size() - 1) {
                                BlockChain.addTransaction(m.getTo().getWallet().sendFunds(p.getWallet().publicKey, amount));
                                updateamount -= amount;
                            } else {
                                BlockChain.addTransaction(m.getTo().getWallet().sendFunds(p.getWallet().publicKey, updateamount));
                            }
                            indx++;
                        }

                        if (time.containsKey(m.toString())) {
                            Tuple<Double, Double> waktu = time.get(m.toString());
                            if (waktu.getValue() == -1.0) {
                                time.put(m.toString(), new Tuple(waktu.getKey(), SimClock.getTime()));
                            }
                        }
                        toBeDel.add(m);
                        finished.add(m);
                    }
                }
            }
        }
        for (Message m : toBeDel) {
//            System.out.println("tobedel = " + m);
//            System.out.println("contains key " + pending.containsKey(m));
            pending.remove(m);
        }
    }

    public static void setDeposit(String message, Transaction trx) {
        Tuple<Transaction, Boolean> tup = new Tuple<Transaction, Boolean>(trx, false);
        deposits.put(message, tup);
    }

    public static String do_RSADecryption(byte[] cipherText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");

        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] result = cipher.doFinal(cipherText);

        return new String(result);
    }

    public static Map<Message, List<DTNHost>> getAck() {
        return ack;
    }

    public static Set<DTNHost> getBlacklist() {
        return blacklist;
    }

    public static Map<String, Set<DTNHost>> getTrustToken() {
        return trustToken;
    }

    public static Map<Message, Map<DTNHost, Set<String>>> getVerificating() {
        return verificating;
    }

    public static Map<String, Tuple<Double, Double>> getTime() {
        return time;
    }

    public static double getFinished() {
        double counter = 0;
        for (Message f : finished) {
            for (DTNHost host : f.getHops()) {
                if (isMisbehave(host)) {
                    counter++;
                }
            }
        }
        return counter;
    }

    public static double getOk() {
        return transaksiok;
    }

    public static double getGagal() {
        return transaksigagal;
    }

    private static boolean isMisbehave(DTNHost otherHost) {
        if (otherHost.toString().startsWith("Mis")) {
            return true;
        }
        return false;
    }

    public static int getJumlahVerificator() {
        return jumlahVerificator;
    }
    
    
    

}
