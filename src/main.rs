use eyre::Result;
use primitive_types::{H160, H256};
use std::{collections::HashMap, str::FromStr};
use tokio::runtime::Runtime;
use tracing::{debug, Level};

use ethers::{
    types::{BigEndianHash, BlockId},
    utils::keccak256,
};
use ethers_providers::{Http, Middleware, Provider};

use revm::{
    interpreter::{opcode, CallInputs, Gas, InstructionResult, Interpreter},
    primitives::{AccountInfo, Bytecode, Bytes, TransactTo, B160, KECCAK_EMPTY, U256},
    Database, EVMData, InMemoryDB, Inspector,
};

#[derive(Debug)]
pub struct ForkInspector {
    address_cache: HashMap<B160, AccountInfo>,
    address_slot_cache: HashMap<(B160, U256), U256>,
    provider: Provider<Http>,
    block_id: Option<BlockId>,
    runtime: Runtime,
}

impl ForkInspector {
    pub fn new(provider: Provider<Http>, block_id: Option<u64>, runtime: Runtime) -> Self {
        Self {
            address_cache: HashMap::new(),
            address_slot_cache: HashMap::new(),
            provider,
            block_id: block_id.map(BlockId::from),
            runtime,
        }
    }

    pub fn load_address(&mut self, contract: B160) -> Result<AccountInfo> {
        if let Some(account) = self.address_cache.get(&contract) {
            Ok(account.clone())
        } else {
            debug!("Loading data for address: {:?}", contract);

            let address = H160::from(*contract);
            let block_id = self.block_id;
            let balance = self.provider.get_balance(address, block_id);
            let balance = self.runtime.block_on(balance)?.into();

            let code = self.provider.get_code(address, block_id);
            let code: ethers::types::Bytes = self.runtime.block_on(code)?;

            let nonce = self.provider.get_transaction_count(address, block_id);
            let nonce: u64 = self.runtime.block_on(nonce)?.as_u64();

            let (code, code_hash) = if !code.0.is_empty() {
                (Some(code.0.clone()), keccak256(&code).into())
            } else {
                (Some(Bytes::default()), KECCAK_EMPTY)
            };

            let account = AccountInfo {
                balance,
                nonce,
                code: code.map(|bytes| Bytecode::new_raw(bytes).to_checked()),
                code_hash,
            };

            self.address_cache.insert(contract, account.clone());
            Ok(account)
        }
    }
}

impl Inspector<InMemoryDB> for ForkInspector {
    fn call(
        &mut self,
        data: &mut EVMData<'_, InMemoryDB>,
        inputs: &mut CallInputs,
        _is_static: bool,
    ) -> (InstructionResult, Gas, Bytes) {
        let contract = inputs.contract;

        debug!("Maybe load data for address: {:?}", contract);

        let loaded = matches!(data.db.basic(contract), Ok(Some(_)));
        if !loaded && !self.address_cache.contains_key(&contract) {
            debug!("Loading data for address: {:?}", contract);

            let address = H160::from(*contract);
            let block_id = self.block_id;
            let balance = self.provider.get_balance(address, block_id);
            let balance = self.runtime.block_on(balance).unwrap().into();

            let code = self.provider.get_code(address, block_id);
            let code: ethers::types::Bytes = self.runtime.block_on(code).unwrap();

            let nonce = self.provider.get_transaction_count(address, block_id);
            let nonce: u64 = self.runtime.block_on(nonce).unwrap().as_u64();

            let (code, code_hash) = if !code.0.is_empty() {
                (Some(code.0.clone()), keccak256(&code).into())
            } else {
                (Some(Bytes::default()), KECCAK_EMPTY)
            };

            let account = AccountInfo {
                balance,
                nonce,
                code: code.map(|bytes| Bytecode::new_raw(bytes).to_checked()),
                code_hash,
            };

            self.address_cache.insert(contract, account.clone());
            data.db.insert_account_info(contract, account);
        }

        (InstructionResult::Continue, Gas::new(0), Bytes::new())
    }

    fn step(
        &mut self,
        interp: &mut Interpreter,
        data: &mut EVMData<'_, InMemoryDB>,
        _is_static: bool,
    ) -> InstructionResult {
        let opcode = interp.current_opcode();
        let b_address = interp.contract.address;
        let pc = interp.program_counter();
        let address = H160::from(*b_address);

        debug!(
            "ForkInspector: address {:?} pc {:?} opcode: {:?}",
            address, pc, opcode
        );

        // NOTE assuming call always appears before sload for a new address
        if self.address_cache.contains_key(&b_address) {
            match opcode {
                opcode::SLOAD => {
                    let b_idx: U256 =
                        interp.stack.peek(0).expect("Missing index for SLOAD");

                    if let std::collections::hash_map::Entry::Vacant(e) = self
                        .address_slot_cache.entry((b_address, b_idx)) {
                            debug!("SLOAD: {:?} {:?}", b_address, b_idx);
                            let block_id = self.block_id;
                            let idx = H256::from_uint(&b_idx.into());
                            let storage = self
                                .provider
                                .get_storage_at(address, idx, block_id);
                            let value = self
                                .runtime
                                .block_on(storage)
                                .expect("Provider error: failed to get storage ");

                            let value = value.into_uint();

                            data.db
                                .insert_account_storage(
                                    b_address,
                                    b_idx,
                                    value.into(),
                                )
                                .expect("Set account storage failed!");

                            e.insert(value.into());
                        }
                }
                opcode::CALL // calls, address is the second argument
                    | opcode::CALLCODE
                    | opcode::DELEGATECALL
                    | opcode::STATICCALL
                    | opcode::EXTCODECOPY // others, address is the first argument
                    | opcode::EXTCODESIZE
                    | opcode::EXTCODEHASH
                    | opcode::SELFDESTRUCT
                    | opcode::BALANCE =>  {
                        let contract = match opcode{
                            opcode::CALL
                                | opcode::CALLCODE
                                | opcode::DELEGATECALL
                                | opcode::STATICCALL =>
                                interp.stack.peek(1).expect("Missing address for CALL type of opcodes"),
                            _ => interp.stack.peek(0).expect("Missing address for non-CALL type of opcodes")
                        };

                        let contract = {
                            let bytes: &[u8; 32] = &contract.to_be_bytes();
                            B160::from_slice(&bytes[12..])
                        };


                        debug!("Maybe load data for address: {:?}", contract);



                        let loaded =
                            matches!(data.db.basic(contract), Ok(Some(_)));

                        if !loaded{
                            let account = self.load_address(contract).unwrap();
                            data.db.insert_account_info(contract, account);
                        }
                    }
                _ => {}
            }
        }

        InstructionResult::Continue
    }

    fn step_end(
        &mut self,
        _interp: &mut Interpreter,
        _data: &mut EVMData<'_, InMemoryDB>,
        _is_static: bool,
        _eval: InstructionResult,
    ) -> InstructionResult {
        println!("ForkInspector: step_end");
        InstructionResult::Continue
    }
}

fn transact_with_inspector() -> Result<()> {
    let runtime = Runtime::new().unwrap();
    let provider =
        Provider::<Http>::try_from("https://eth.llamarpc.com").expect("Failed to create provider");

    let n = runtime.block_on(provider.get_block_number()).unwrap();

    println!("Current block number: {:?}", n);

    let mut inspector = ForkInspector::new(provider, Some(17890805), runtime);
    let sender = H160::from_str("0x36928500bc1dcd7af6a2b4008875cc336b927d57")?;
    let contract = H160::from_str("0xdac17f958d2ee523a2206206994597c13d831ec7")?;
    let mut evm = revm::new();
    let mut db = InMemoryDB::default();

    let sender_account = inspector.load_address(sender.into())?;
    let contract_account = inspector.load_address(contract.into())?;

    db.insert_account_info(sender.into(), sender_account);
    db.insert_account_info(contract.into(), contract_account);

    evm.database(db);
    evm.env.tx.caller = sender.into();
    evm.env.tx.transact_to = TransactTo::Call(contract.into());
    evm.env.tx.data =
        hex::decode("70a08231000000000000000000000000f977814e90da44bfa03b6295a0616a897441acec")?
            .into();

    let result = evm.inspect_commit(inspector);

    println!("Result: {:?}", result);

    Ok(())
}

fn main() {
    let collector = tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .finish();

    tracing::subscriber::set_global_default(collector).unwrap();

    transact_with_inspector().unwrap();
}
