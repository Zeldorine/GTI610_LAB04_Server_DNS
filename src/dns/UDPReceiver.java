package dns;

import java.io.ByteArrayInputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Cette classe permet la reception d'un paquet UDP sur le port de reception
 * UDP/DNS. Elle analyse le paquet et extrait le hostname
 *
 * Il s'agit d'un Thread qui ecoute en permanance pour ne pas affecter le
 * deroulement du programme
 *
 * @author Max
 *
 */
public class UDPReceiver extends Thread {

    /**
     * Les champs d'un Packet UDP -------------------------- En-tete (12
     * octects) Question : l'adresse demande Reponse : l'adresse IP Autorite :
     * info sur le serveur d'autorite Additionnel : information supplementaire
     */
    /**
     * Definition de l'En-tete d'un Packet UDP
     * --------------------------------------- Identifiant Parametres QDcount
     * Ancount NScount ARcount
     *
     * L'identifiant est un entier permettant d'identifier la requete.
     * parametres contient les champs suivant : QR (1 bit) : indique si le
     * message est une question (0) ou une reponse (1). OPCODE (4 bits) : type
     * de la requete (0000 pour une requete simple). AA (1 bit) : le serveur qui
     * a fourni la reponse a-t-il autorite sur le domaine? TC (1 bit) : indique
     * si le message est tronque. RD (1 bit) : demande d'une requete recursive.
     * RA (1 bit) : indique que le serveur peut faire une demande recursive.
     * UNUSED, AD, CD (1 bit chacun) : non utilises. RCODE (4 bits) : code de
     * retour. 0 : OK, 1 : erreur sur le format de la requete, 2: probleme du
     * serveur, 3 : nom de domaine non trouve (valide seulement si AA), 4 :
     * requete non supportee, 5 : le serveur refuse de repondre (raisons de
     * s?ecurite ou autres). QDCount : nombre de questions. ANCount, NSCount,
     * ARCount : nombre d?entrees dans les champs ?Reponse?, Autorite,
     * Additionnel.
     */
    protected final static int BUF_SIZE = 2048;
    protected String SERVER_DNS = null;//serveur de redirection (ip)
    protected int portRedirect = 53; // port  de redirection (par defaut)
    protected int port; // port de r?ception
    private final String adrIP = null; //bind ip d'ecoute
    private String DomainName = "none";
    private String DNSFile = null;
    private boolean RedirectionSeulement = false;

    private class ClientInfo { //quick container

        public String client_ip = null;
        public int client_port = 0;
    };
    private final HashMap<Integer, ClientInfo> Clients = new HashMap<>();

    private final boolean stop = false;

    private static final int QR_MASK = 0b10000000;

    public UDPReceiver() {
    }

    public UDPReceiver(String SERVER_DNS, int Port) {
        this.SERVER_DNS = SERVER_DNS;
        this.port = Port;
    }

    public void setport(int p) {
        this.port = p;
    }

    public void setRedirectionSeulement(boolean b) {
        this.RedirectionSeulement = b;
    }

    public String gethostNameFromPacket() {
        return DomainName;
    }

    public String getAdrIP() {
        return adrIP;
    }

    public String getSERVER_DNS() {
        return SERVER_DNS;
    }

    public void setSERVER_DNS(String server_dns) {
        this.SERVER_DNS = server_dns;
    }

    public void setDNSFile(String filename) {
        DNSFile = filename;
    }

    @Override
    public void run() {
        try {
            DatagramSocket serveur = new DatagramSocket(this.port); // *Creation d'un socket UDP

            // *Boucle infinie de recpetion
            while (!this.stop) {
                byte[] buff = new byte[0x1FF];
                DatagramPacket paquetRecu = new DatagramPacket(buff, buff.length);
                System.out.println("Serveur DNS  " + serveur.getLocalAddress() + "  en attente sur le port: " + serveur.getLocalPort());

                // *Reception d'un paquet UDP via le socket
                serveur.receive(paquetRecu);
                System.out.println("\n\npaquet recu du  " + paquetRecu.getAddress() + "  du port: " + paquetRecu.getPort());

                // *Creation d'un DataInputStream ou ByteArrayInputStream pour manipuler les bytes du paquet
                ByteArrayInputStream TabInputStream = new ByteArrayInputStream(paquetRecu.getData());

                int identifiant = getIdentifiant(TabInputStream);

                // ****** Dans le cas d'un paquet requete *****
                if (TabInputStream.read() == 1) {
                    // *Lecture du Query Domain name, a partir du 13 byte
                    TabInputStream.skip(10);
                    initQueryDomainName(TabInputStream);

                    // *Sauvegarde de l'adresse, du port et de l'identifiant de la requete
                    ClientInfo clientInfo = new ClientInfo();
                    clientInfo.client_ip = paquetRecu.getAddress().toString().substring(1);
                    clientInfo.client_port = paquetRecu.getPort();
                    Clients.put(identifiant, clientInfo);

                    // *Si le mode est redirection seulement
                    if (RedirectionSeulement) {
                        // *Rediriger le paquet vers le serveur DNS
                        DatagramPacket packet = new DatagramPacket(buff, buff.length, new InetSocketAddress(SERVER_DNS, portRedirect));
                        serveur.send(packet);
                    } else {
                        // *Rechercher l'adresse IP associe au Query Domain name dans le fichier de correspondance de ce serveur					
                        List<String> ipFound = new ArrayList<>();
                        if (DNSFile != null) {
                            QueryFinder queryFinder = new QueryFinder(DNSFile);
                            ipFound = queryFinder.StartResearch(DomainName);
                        }

                        // *Si la correspondance n'est pas trouvee
                        if (ipFound.isEmpty()) {
                            // *Rediriger le paquet vers le serveur DNS
                            DatagramPacket packet = new DatagramPacket(buff, buff.length, new InetSocketAddress(SERVER_DNS, portRedirect));
                            serveur.send(packet);
                        } else {
                            // *Creer le paquet de reponse a l'aide du UDPAnswerPaquetCreator
                            byte[] paquetReponse = UDPAnswerPacketCreator.getInstance().CreateAnswerPacket(buff, ipFound);
                            ClientInfo client = Clients.get(identifiant);
                            DatagramPacket packet = new DatagramPacket(paquetReponse, paquetReponse.length, new InetSocketAddress(client.client_ip, client.client_port));

                            // *Placer ce paquet dans le socket et Envoyer le paquet
                            serveur.send(packet);
                        }
                    }

                    // ****** Dans le cas d'un paquet reponse *****
                } else {
                    // recuperer la valeur de ANCount
                    TabInputStream.skip(3);
                    int ANCount = getANCount(TabInputStream);

                    // *Lecture du Query Domain name, a partir du 13 byte
                    TabInputStream.skip(5);
                    initQueryDomainName(TabInputStream);

                    // *Passe par dessus Type et Class
                    TabInputStream.skip(4);

                    // *Passe par dessus les premiers champs du ressource record
                    // pour arriver au ressource data qui contient l'adresse IP associe au hostname (dans le fond saut de 16 bytes)
                    TabInputStream.skip(11);

                    List<String> ipAddresses = getIpReponses(TabInputStream, ANCount);

                    // *Capture de ou des adresse(s) IP (ANCOUNT est le nombre de r?ponses retourn?es)	
                    // *Ajouter la ou les correspondance(s) dans le fichier DNS si elles ne y sont pas deja
                    AnswerRecorder answer = new AnswerRecorder(DNSFile);

                    ipAddresses.stream().forEach((ip) -> {
                        if (enregistrerIp(ip)) {
                            answer.StartRecord(DomainName, ip);
                        }
                    });

                    // *Faire parvenir le paquet reponse au demandeur original, ayant emis une requete avec cet identifiant				
                    // *Placer ce paquet dans le socket et Envoyer le paquet
                    ClientInfo client = Clients.get(identifiant);
                    byte[] paquetReponse = UDPAnswerPacketCreator.getInstance().CreateAnswerPacket(buff, ipAddresses);

                    if (paquetReponse != null && checkClientInfoNotNUll(client)) {
                        serveur.send(new DatagramPacket(paquetReponse, paquetReponse.length, new InetSocketAddress(client.client_ip, client.client_port)));
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Probl?me ? l'ex?cution :");
            e.printStackTrace(System.err);
        }
    }

    private boolean enregistrerIp(String ip) {
        QueryFinder queryFinder = new QueryFinder(DNSFile);
        List<String> ipFound = queryFinder.StartResearch(DomainName);
        
        return !ipFound.contains(ip);
    }

    private boolean checkClientInfoNotNUll(ClientInfo client) {
        return client != null && client.client_ip != null && client.client_port > 0;
    }

    private int getIdentifiant(ByteArrayInputStream TabInputStream) {
        int identifiant = 0;

        int identifiant1 = TabInputStream.read();
        if (identifiant1 != 0) {
            identifiant += identifiant1;
        }

        identifiant = identifiant << 8;

        int identifiant2 = TabInputStream.read();
        if (identifiant2 != 0) {
            identifiant += identifiant2;
        }

        return identifiant;
    }

    private int getANCount(ByteArrayInputStream TabInputStream) {
        int ANCount = 0;

        int tmpByte = TabInputStream.read();
        if (tmpByte != 0) {
            ANCount += tmpByte;
        }
        ANCount = ANCount << 8;
        tmpByte = TabInputStream.read();
        if (tmpByte != 0) {
            ANCount += tmpByte;
        }

        return ANCount;
    }

    private void initQueryDomainName(ByteArrayInputStream TabInputStream) {
        int tmpbyte = (char) TabInputStream.read();
        StringBuilder stringBUilder = new StringBuilder();
        DomainName = "";

        while (tmpbyte != 0) {
            //http://www.codeproject.com/Articles/46603/A-PicRS-control-with-a-PIC-microcontroller-seri
            //Transformer nimporte quelle caractere entre 0 - 46 en '.'. Octet 00 marque la fin donc tmpByte = 0
            if (tmpbyte != 0 && tmpbyte < 46) {
                tmpbyte = 46;
            }

            if (tmpbyte != 0) {
                stringBUilder.append(Character.toString((char) tmpbyte));
            }

            tmpbyte = (char) TabInputStream.read();
        }

        DomainName = stringBUilder.toString();
    }

    private List<String> getIpReponses(ByteArrayInputStream TabInputStream, int ANCount) {
        String[] tmpIpAddresses = new String[ANCount];
        List<String> ipAddresses = new ArrayList<>();
        int nbIp = 0;
        int index = 0;

        while (nbIp < ANCount) {
            // 4 octect pour une adresse IPV4
            int rdLength = TabInputStream.read();
            if (rdLength == 4) {
                tmpIpAddresses[index] = "";
                for (int i = 0; i < 4; i++) {
                    tmpIpAddresses[index] += Integer.toString(TabInputStream.read());
                    if (i < 3) {
                        tmpIpAddresses[index] += ".";
                    }
                }
                index++;
                TabInputStream.skip(11);
            } else {
                TabInputStream.skip(11 + rdLength);
            }
            nbIp++;
        }

        // Supprimer les string null s'il y en a
        for (int i = 0; i < index; i++) {
            ipAddresses.add(tmpIpAddresses[i]);
        }

        return ipAddresses;
    }
}
