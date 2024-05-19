package com.delnorte.smartcontract.token.ft;

import com.delnorte.smartcontract.wallet.Contract;
import com.iwebpp.crypto.TweetNaclFast;
import org.ton.java.address.Address;
import org.ton.java.cell.Cell;
import org.ton.java.cell.CellBuilder;
import org.ton.java.smartcontract.token.ft.JettonMinter;
import org.ton.java.smartcontract.token.nft.NftUtils;
import org.ton.java.smartcontract.types.ExternalMessage;
import org.ton.java.smartcontract.types.JettonMinterData;
import org.ton.java.smartcontract.types.WalletCodes;
import org.ton.java.smartcontract.types.WalletVersion;
import org.ton.java.smartcontract.wallet.Options;
import org.ton.java.smartcontract.wallet.Wallet;
import org.ton.java.smartcontract.wallet.WalletContract;
import org.ton.java.tonlib.Tonlib;
import org.ton.java.tonlib.types.*;
import org.ton.java.utils.Utils;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.Deque;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

public class DTVMinter implements Contract {

    Options options;

    Address address;

    public DTVMinter(Options options) {
        this.options=options;
        this.options.wc = 0;

        if (nonNull(options.address)) {
            this.address = options.address;
        }

        if (isNull(options.code)) {
            options.code = CellBuilder.beginCell().fromBoc(WalletCodes.jettonMinter.getValue()).endCell();
        }
    }

    public String getName() {
        return  "DTVMinter";
    }
    @Override
    public Options getOptions() {
        return options;
    }

    @Override
    public Address getAddress() {
        if (isNull(address)) {
            return (createStateInit()).address;
        }
        return address;
    }
    @Override
    public Cell createDataCell() {
        CellBuilder cell = CellBuilder.beginCell();
        cell.storeCoins(BigInteger.ZERO);
        cell.storeAddress(options.adminAddress);
        cell.storeRef(NftUtils.createOffchainUriCell(options.jettonContentUri));
        cell.storeRef(CellBuilder.beginCell().fromBoc(options.jettonWalletCodeHex).endCell());
        return cell.endCell();
    }

    public Cell createMintBody(long queryId, Address destination, BigInteger amount, BigInteger jettonAmount) {
        return createMintBody(queryId, destination, amount, jettonAmount, null, null, BigInteger.ZERO);
    }

    public Cell createMintBody(long queryId, Address destination, BigInteger amount, BigInteger jettonAmount,
                               Address fromAddress, Address responseAddress, BigInteger forwardAmount) {
        CellBuilder body = CellBuilder.beginCell();
        body.storeUint(21, 32);
        body.storeUint(queryId, 64);
        body.storeAddress(destination);
        body.storeCoins(amount);

        CellBuilder transferBody = CellBuilder.beginCell();
        transferBody.storeUint(0x178d4519, 32);
        transferBody.storeUint(queryId, 64);
        transferBody.storeCoins(jettonAmount);
        transferBody.storeAddress(fromAddress);
        transferBody.storeAddress(responseAddress);
        transferBody.storeBit(false);

        body.storeRef(transferBody.endCell());

        return body.endCell();
    }

    public Cell createChangedAdminBody(long queryId, Address newAdminAddress) {
        if (isNull(newAdminAddress)) {
            throw  new Error("Specify newAdminAddress");
        }

        CellBuilder body = CellBuilder.beginCell();
        body.storeUint(3, 32);
        body.storeUint(queryId, 64);
        body.storeAddress(newAdminAddress);

        return body.endCell();
    }

    public Cell createEditContentBody(String jettonContentUri, long queryId) {
        CellBuilder body = CellBuilder.beginCell();
        body.storeUint(4, 32); // OP change content
        body.storeUint(queryId, 64); // query_id
        body.storeRef(NftUtils.createOffchainUriCell(jettonContentUri));
        return body.endCell();
    }

    public JettonMinterData getJettonData(Tonlib tonlib) {
        Address myAddress = this.getAddress();
        RunResult result = tonlib.runMethod(myAddress, "get_jetton_data"); // minter

        if (result.getExit_code() != 0) {
            throw new Error("method get_nft_data, returned an exit code:"+result.getExit_code());
        }

        TvmStackEntryNumber totalSupplyNumber = (TvmStackEntryNumber) result.getStack().get(0);
        BigInteger totalSupply = totalSupplyNumber.getNumber();

        System.out.println("minter totalSupply:"+ Utils.formatNanoValue(totalSupply));

        boolean isMutable = ((TvmStackEntryNumber)result.getStack().get(1)).getNumber().longValue() == -1;

        TvmStackEntrySlice adminAddr = (TvmStackEntrySlice) result.getStack().get(2);
        Address adminAddress = NftUtils.parseAddress(CellBuilder.beginCell().fromBoc(
                Utils.base64ToBytes(adminAddr.getSlice().getBytes())).endCell());

        TvmStackEntryCell jettonContent = (TvmStackEntryCell) result.getStack().get(3);
        Cell jettonContentCell = CellBuilder.beginCell().fromBoc(
                Utils.base64ToBytes(jettonContent.getCell().getBytes())).endCell();
        String jettonContentUri = null;
        try {
            jettonContentUri = NftUtils.parseOffchainUriCell(jettonContentCell);
        }
        catch (Exception e) {
            System.out.println("exception:"+e);
        }

        TvmStackEntryCell contentC = (TvmStackEntryCell) result.getStack().get(4);
        Cell jettonWalletCode = CellBuilder.beginCell().fromBoc(Utils.base64ToBytes(contentC.getCell().getBytes()))
                                .endCell();

        return JettonMinterData.builder()
                .totalSupply(totalSupply)
                .isMutable(isMutable)
                .adminAddress(adminAddress)
                .jettonContentUri(jettonContentUri)
                .jettonWalletCode(jettonWalletCode)
                .build();
    }

    public BigInteger getTotalSupply(Tonlib tonlib) {
        Address myAddress = this.getAddress();
        RunResult result = tonlib.runMethod(myAddress, "get_jetton_data");

        if (result.getExit_code() != 0) {
            throw new Error("method get_jetton_data, returned an exit code "+result.getExit_code());
        }

        TvmStackEntryNumber totalSupplyNumber = (TvmStackEntryNumber) result.getStack().get(0);
        return totalSupplyNumber.getNumber();
    }

    public Address getJettonWalletAddress(Tonlib tonlib, Address ownerAddress) {
        Address myAddress = this.getAddress();
        CellBuilder cell = CellBuilder.beginCell();
        cell.storeAddress(ownerAddress);

        Deque<String> stack = new ArrayDeque<>();

        stack.offer("[slice, "+cell.endCell().toHex(true)+"]");

        RunResult result = tonlib.runMethod(myAddress, "get_wallet_address", stack);

        if (result.getExit_code() != 0) {
            throw new Error("method get_jetton_data, returned an exit code "+result.getExit_code());
        }

        TvmStackEntrySlice addr = (TvmStackEntrySlice) result.getStack().get(0);
        return NftUtils.parseAddress(CellBuilder.beginCell().fromBoc(Utils.base64ToBytes(addr.getSlice().getBytes())).endCell());
    }

    public ExtMessageInfo deploy(Tonlib tonlib, WalletContract adminWallet, BigInteger walletMsgValue, TweetNaclFast.Signature.KeyPair keyPair) {
        long seqno = adminWallet.getSeqno(tonlib);

        ExternalMessage externalMessage = adminWallet.createTransferMessage(
                keyPair.getSecretKey(),
                this.getAddress(),
                walletMsgValue,
                seqno,
                (Cell) null,
                (byte) 3,
                this.createStateInit().stateInit);

        return tonlib.sendRawMessage(Utils.bytesToBase64(externalMessage.message.toBoc()));
    }

    public void mint(Tonlib tonlib, WalletContract adminWallet, Address destination, BigInteger walletMsgValue, BigInteger mintMsgValue,
                     BigInteger jettonToMintAmount, TweetNaclFast.Signature.KeyPair keyPair) {

        long seqno = adminWallet.getSeqno(tonlib);

        ExternalMessage externalMessage = adminWallet.createTransferMessage(
                keyPair.getSecretKey(),
                this.getAddress(),
                walletMsgValue,
                seqno,
                this.createMintBody(0, destination, mintMsgValue, jettonToMintAmount));


        tonlib.sendRawMessage(Utils.bytesToBase64(externalMessage.message.toBoc()));
    }

/*
    private JettonMinter delployMinter() {


        Options options = Options.builder()
                .adminAddress(adminWallet.getWallet().getAddress())
                .jettonContentUri("https://raw.githubusercontent.com/neodix42/ton4j/main/1-media/neo-jetton.json")
                .jettonWalletCodeHex(WalletCodes.jettonWallet.getValue())
                .build();

        Wallet jettonMinter = new Wallet(WalletVersion.jettonMinter, options);
        JettonMinter minter = jettonMinter.create();
        log.info("jetton minter address {} {}", minter.getAddress().toString(true, true, true), minter.getAddress().toString(false));
        ExtMessageInfo extMessageInfo = minter.deploy(tonlib, adminWallet.getWallet(), Utils.toNano(0.05), adminWallet.getKeyPair());
        assertThat(extMessageInfo.getError().getCode()).isZero();

        Utils.sleep(40);
        return minter;
    }
*/
    public static void main(String[] args) {
        Address ownerAddr = new Address("0QAiuh3GMassnL5yPSW8AMlLCUN2iZavPlgpBTjLZ8F3R23Y");
        Options options = Options.builder().address(ownerAddr).build();
        DTVMinter dtv = new DTVMinter(options);

    }
}
