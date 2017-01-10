package com.codus.hello;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.util.Date;
import java.util.List;
import java.util.TreeMap;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.CheckpointManager;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.net.discovery.DnsDiscovery;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.SPVBlockStore;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.KeyChain;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.UnreadableWalletException;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.Wallet.BalanceType;
import org.bitcoinj.wallet.Wallet.SendResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Charsets;
import com.google.common.base.Joiner;

public class HelloWorld {
  
  private static final String SPV_BLOCKCHAIN_SUFFIX = ".svp";
  
  private static final File PLAIN_CHECKPOINTS_FILE = new File("mbhd.checkpoints"); 
  private static final File TEXTUAL_CHECKPOINTS_FILE = new File("mbhd.checkpoints.txt"); 
  private static final String filePrefix = "multibit-hardware";
  private static final String blockchainFilename = filePrefix + SPV_BLOCKCHAIN_SUFFIX;
  private static final File BLOCK_STORE_FILE = new File(blockchainFilename);
  
  static Logger logger = LoggerFactory.getLogger("HelloWorld");
  
  static NetworkParameters params = new MainNetParams();
  
  public static void cleanBlockstores() {
    File blockStoreFile = new File(blockchainFilename);
    logger.info("Cleaning block stores in " + blockStoreFile +", " + PLAIN_CHECKPOINTS_FILE);
    if (blockStoreFile.exists()) {
      blockStoreFile.delete();
    }
    
    if (PLAIN_CHECKPOINTS_FILE.exists()) {
      PLAIN_CHECKPOINTS_FILE.delete();
    }
  }
  
  private static BlockStore createBlockStore(Date replayDate, NetworkParameters networkParameters) throws BlockStoreException, IOException {
    BlockStore blockStore = null;
    boolean blockStoreCreatedNew = !BLOCK_STORE_FILE.exists();

    // Ensure there is a checkpoints file.
    File checkpointsFile = PLAIN_CHECKPOINTS_FILE;

    logger.debug("{} SPV block store '{}' from disk", blockStoreCreatedNew ? "Creating" : "Opening", blockchainFilename);
    try {
      blockStore = new SPVBlockStore(networkParameters, BLOCK_STORE_FILE);
    } catch (BlockStoreException bse) {
      throw new RuntimeException(bse);
    }

    // Load the existing checkpoint file and checkpoint from today.
    if (blockStore != null && checkpointsFile.exists()) {
      FileInputStream stream = null;
      try {
        stream = new FileInputStream(checkpointsFile);
        if (replayDate == null) {
          if (blockStoreCreatedNew) {
            // Brand new block store - checkpoint from today. This
            // will go back to the last checkpoint.
            CheckpointManager.checkpoint(networkParameters, stream, blockStore, (new Date()).getTime() / 1000);
          }
        } else {
          // Use checkpoint date (block replay).
          CheckpointManager.checkpoint(networkParameters, stream, blockStore, replayDate.getTime() / 1000);
        }
      } finally {
        if (stream != null) {
          stream.close();
        }
      }
    }
    return blockStore;
  }

  private static void writeBinaryCheckpoints(TreeMap<Integer, StoredBlock> checkpoints, File file) throws Exception {
    FileOutputStream fileOutputStream = null;
    try {
      fileOutputStream = new FileOutputStream(file, false);
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      final DigestOutputStream digestOutputStream = new DigestOutputStream(fileOutputStream, digest);
      digestOutputStream.on(false);
      final DataOutputStream dataOutputStream = new DataOutputStream(digestOutputStream);
      dataOutputStream.writeBytes("CHECKPOINTS 1");
      dataOutputStream.writeInt(0); // Number of signatures to read. Do this later.
      digestOutputStream.on(true);
      dataOutputStream.writeInt(checkpoints.size());
      ByteBuffer buffer = ByteBuffer.allocate(StoredBlock.COMPACT_SERIALIZED_SIZE);
      for (StoredBlock block : checkpoints.values()) {
        block.serializeCompact(buffer);
        dataOutputStream.write(buffer.array());
        buffer.position(0);
      }
      dataOutputStream.close();
      Sha256Hash checkpointsHash = Sha256Hash.wrap(digest.digest());
      System.out.println("Hash of checkpoints data is " + checkpointsHash);
      digestOutputStream.close();
      fileOutputStream.close();
      System.out.println("Checkpoints written to '" + file.getCanonicalPath() + "'.");
    } finally {
      if (fileOutputStream != null) {
        fileOutputStream.close();
      }
    }
  }

  private static void writeTextualCheckpoints(TreeMap<Integer, StoredBlock> checkpoints, File file) throws IOException {
    PrintWriter writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(file), Charsets.US_ASCII));
    writer.println("TXT CHECKPOINTS 1");
    writer.println("0"); // Number of signatures to read. Do this later.
    writer.println(checkpoints.size());
    ByteBuffer buffer = ByteBuffer.allocate(StoredBlock.COMPACT_SERIALIZED_SIZE);
    for (StoredBlock block : checkpoints.values()) {
      block.serializeCompact(buffer);
      writer.println(CheckpointManager.BASE64.encode(buffer.array()));
      buffer.position(0);
    }
    writer.close();
    System.out.println("Checkpoints written to '" + file.getCanonicalPath() + "'.");
  }
  
  public static Wallet newWallet() {
    Wallet wallet = new Wallet(params);
    return wallet;
  }

  public static Wallet fromSeed(String seedCode, long creationTime) throws UnreadableWalletException {
    DeterministicSeed seed = new DeterministicSeed(seedCode, null, "", creationTime);
    return Wallet.fromSeed(params, seed);
  }
  
  public static Address newAddress() {
    ECKey key = new ECKey();
    Address address = new Address(params, key.getPubKeyHash());
    return address;
  }
  
  public static BlockStore reloadBlockChain(long creationTime, Wallet wallet) throws Exception {
    BlockStore blockStore = createBlockStore(new Date(creationTime * 1000), params);

    BlockChain chain = new BlockChain(params, wallet, blockStore);

    final TreeMap<Integer, StoredBlock> checkpoints = new TreeMap<Integer, StoredBlock>();
    final long oneDayBack = creationTime - (86400 * 1);

    chain.addNewBestBlockListener(Threading.SAME_THREAD, (block) -> {
      int height = block.getHeight();
      if (height % params.getInterval() == 0 && block.getHeader().getTimeSeconds() <= oneDayBack) {
        System.out.println(String.format("Checkpointing block %s at height %d num blocks: %d", block.getHeader().getHash(), block.getHeight(),
            checkpoints.size() + 1));
        checkpoints.put(height, block);
      }
    });

    PeerGroup peerGroup = new PeerGroup(params, chain);
    peerGroup.addWallet(wallet);
    peerGroup.setUserAgent("BitToy", "0.1");
    peerGroup.addPeerDiscovery(new DnsDiscovery(params));
    peerGroup.start();
    peerGroup.downloadBlockChain();

    System.out.println("Checkpoints:" + checkpoints.size());

    // Write checkpoint data out.
    if (!PLAIN_CHECKPOINTS_FILE.exists()) {
      writeBinaryCheckpoints(checkpoints, PLAIN_CHECKPOINTS_FILE);
      writeTextualCheckpoints(checkpoints, TEXTUAL_CHECKPOINTS_FILE);
    }
    logger.info("Done loading blockchain");
    return blockStore;
  }
  
  public static final void displayWallet(Wallet wallet, String assertAddress) {
    System.out.println(wallet.getKeyChainSeed());
    System.out.println("keys:" + wallet.currentReceiveKey().toStringWithPrivate(params));

    DeterministicSeed seed2 = wallet.getKeyChainSeed();
    System.out.println("Seed words are: " + Joiner.on(" ").join(seed2.getMnemonicCode()));
    System.out.println("Seed birthday is: " + seed2.getCreationTimeSeconds());
    System.out.println("Private key:" + wallet.currentReceiveKey().toStringWithPrivate(params));
    System.out.println("receive address:" + wallet.currentReceiveAddress());
    System.out.println("assert address: " + assertAddress);
    System.out.println("Change address:" + wallet.currentChangeAddress());
    System.out.println("Change Private key:" + wallet.currentKey(KeyChain.KeyPurpose.CHANGE).toStringWithPrivate(params));
    
    // Example addresses and keys :
    System.out.println("Example addresses : ");
    
    
    List<DeterministicKey> keys = wallet.freshKeys(KeyChain.KeyPurpose.CHANGE, 10);
    keys.forEach(key -> {
      Address address = new Address(params, key.getPubKeyHash());
      System.out.println(address +" : " + key.getPublicKeyAsHex());
    });
    
    if (!wallet.currentReceiveAddress().toBase58().equals(assertAddress)) {
      throw new RuntimeException("Wallet and assert address don't match:" + wallet.currentReceiveAddress().toBase58() +" vs " + assertAddress);
    }
  }
  
  public static void showBalanceForever(Wallet wallet) throws InterruptedException {
    while(true) {
      System.out.println("balance:" + wallet.getBalance() +" estimated:" + wallet.getBalance(BalanceType.ESTIMATED));
      Thread.sleep(5000);
    }
  }
  
  public static File getWalletFile(String assertAddress, long creationTime, int version) {
    String walletFilename = assertAddress+"." + creationTime + ".v" + version+ ".wallet";
    return new File(walletFilename);
  }
  
  public static Transaction send(Wallet wallet, String destinationAddress, long satoshis) throws Exception {
    Address dest = Address.fromBase58(params, destinationAddress);
    SendRequest request = SendRequest.to(dest, Coin.valueOf(satoshis));
    SendResult result = wallet.sendCoins(request);
    Transaction endTransaction = result.broadcastComplete.get();
    return endTransaction;
  }
  
  public static void main(String[] args) throws Exception {
    // cleanBlockstores();
    final long creationTime = 1484002542;
    Wallet wallet;
    String assertAddress = "1Cpkx2DUPTk5cpYotfT3tmXrJ35BJboPYm";
    String seedCode = "koko baloko";
    wallet = fromSeed(seedCode, creationTime);  
    
    displayWallet(wallet, assertAddress);
    reloadBlockChain(creationTime, wallet);
    
    // Send in case needed. Note that the wallet will generate keys deterministically
    // and thus all funds will stay within the wallet :
//    send(wallet, "1Js7J2oD3GvK2LVAjvib4fSWrQ9N9jNBgk", 35000);
    showBalanceForever(wallet);
  }
}
