/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.pcodeInject;

import ghidra.app.plugin.processors.sleigh.PcodeEmit;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * The "uponentry" injection for a eBPF function.
 * This injects the function prologue which creates the stack frame of size 0x1000.
 * Copied from DEX injection library and modified.
 */
public class InjectPayloadEBPFPrologue implements InjectPayload {
	private String name;
	private String sourceName;
	private InjectParameter[] noParams;

	public InjectPayloadEBPFPrologue(String nm, String srcName) {
		name = nm;
		sourceName = srcName;
		noParams = new InjectParameter[0];
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int getType() {
		return CALLMECHANISM_TYPE;
	}

	@Override
	public String getSource() {
		return sourceName;
	}

	@Override
	public int getParamShift() {
		return 0;
	}

	@Override
	public InjectParameter[] getInput() {
		return noParams;
	}

	@Override
	public InjectParameter[] getOutput() {
		return noParams;
	}

	@Override
	public boolean isErrorPlaceholder() {
		return false;
	}

	@Override
	public void inject(InjectContext context, PcodeEmit emit) {
		// not used
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		PcodeOp[] resOps;
		Function func = program.getFunctionManager().getFunctionContaining(con.baseAddr);

		Register fp = con.language.getRegister("R10");
		Register sp = con.language.getRegister("R11");
		AddressSpace constSpace = program.getAddressFactory().getConstantSpace();
		resOps = new PcodeOp[2];
		
		// add pcode ops that create the stack frame
		// R10 = R11;
		// R11 = R11 - 0x1000;
		PcodeOp op0 = new PcodeOp(con.baseAddr, 0, PcodeOp.COPY);
		op0.setInput(new Varnode(sp.getAddress(), sp.getBitLength()/8), 0);
		op0.setOutput(new Varnode(fp.getAddress(), fp.getBitLength()/8));
		resOps[0] = op0;

		PcodeOp op = new PcodeOp(con.baseAddr, 0, PcodeOp.INT_SUB);
		op.setInput(new Varnode(sp.getAddress(), sp.getBitLength()/8), 0);
		op.setInput(new Varnode(constSpace.getAddress(0x1000), 8), 1);
		op.setOutput(new Varnode(sp.getAddress(), sp.getBitLength()/8));

		resOps[1] = op;
		return resOps;
	}

	@Override
	public boolean isFallThru() {
		return true;
	}

	@Override
	public boolean isIncidentalCopy() {
		return false;
	}

	@Override
	public void saveXml(StringBuilder buffer) {
		// Provide a minimal tag so decompiler can call-back
		buffer.append("<pcode");
		SpecXmlUtils.encodeStringAttribute(buffer, "inject", "uponentry");
		SpecXmlUtils.encodeBooleanAttribute(buffer, "dynamic", true);
		buffer.append("/>\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage language) throws XmlParseException {
		XmlElement el = parser.start();
		String injectString = el.getAttribute("inject");
		if (injectString == null || !injectString.equals("uponentry")) {
			throw new XmlParseException("Expecting inject=\"uponentry\" attribute");
		}
		boolean isDynamic = SpecXmlUtils.decodeBoolean(el.getAttribute("dynamic"));
		if (!isDynamic) {
			throw new XmlParseException("Expecting dynamic attribute");
		}
		parser.end(el);
	}

	@Override
	public boolean isEquivalent(InjectPayload obj) {
		if (getClass() != obj.getClass()) {
			return false;
		}
		InjectPayloadEBPFPrologue op2 = (InjectPayloadEBPFPrologue) obj;
		if (!name.equals(op2.name)) {
			return false;
		}
		if (!sourceName.equals(op2.sourceName)) {
			return false;
		}
		return true;
	}
}
