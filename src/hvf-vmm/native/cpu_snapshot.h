// SPDX-License-Identifier: Apache-2.0
// Schema 1 register set for the non-nested ARM64 device model. IDs are part of
// the file, validated against this exact list before an HVF setter is invoked.
#ifndef HVF_CPU_SNAPSHOT_H
#define HVF_CPU_SNAPSHOT_H
#include "snapshot_io.h"
static const hv_sys_reg_t snapshot_sysregs[]={
    HV_SYS_REG_SMPRI_EL1,HV_SYS_REG_SMCR_EL1,HV_SYS_REG_TPIDR2_EL0,HV_SYS_REG_SCXTNUM_EL0,HV_SYS_REG_SCXTNUM_EL1,
    HV_SYS_REG_DBGBVR0_EL1,
    HV_SYS_REG_DBGBCR0_EL1,
    HV_SYS_REG_DBGWVR0_EL1,
    HV_SYS_REG_DBGWCR0_EL1,
    HV_SYS_REG_DBGBVR1_EL1,
    HV_SYS_REG_DBGBCR1_EL1,
    HV_SYS_REG_DBGWVR1_EL1,
    HV_SYS_REG_DBGWCR1_EL1,
    HV_SYS_REG_MDCCINT_EL1,
    HV_SYS_REG_MDSCR_EL1,
    HV_SYS_REG_DBGBVR2_EL1,
    HV_SYS_REG_DBGBCR2_EL1,
    HV_SYS_REG_DBGWVR2_EL1,
    HV_SYS_REG_DBGWCR2_EL1,
    HV_SYS_REG_DBGBVR3_EL1,
    HV_SYS_REG_DBGBCR3_EL1,
    HV_SYS_REG_DBGWVR3_EL1,
    HV_SYS_REG_DBGWCR3_EL1,
    HV_SYS_REG_DBGBVR4_EL1,
    HV_SYS_REG_DBGBCR4_EL1,
    HV_SYS_REG_DBGWVR4_EL1,
    HV_SYS_REG_DBGWCR4_EL1,
    HV_SYS_REG_DBGBVR5_EL1,
    HV_SYS_REG_DBGBCR5_EL1,
    HV_SYS_REG_DBGWVR5_EL1,
    HV_SYS_REG_DBGWCR5_EL1,
    HV_SYS_REG_DBGBVR6_EL1,
    HV_SYS_REG_DBGBCR6_EL1,
    HV_SYS_REG_DBGWVR6_EL1,
    HV_SYS_REG_DBGWCR6_EL1,
    HV_SYS_REG_DBGBVR7_EL1,
    HV_SYS_REG_DBGBCR7_EL1,
    HV_SYS_REG_DBGWVR7_EL1,
    HV_SYS_REG_DBGWCR7_EL1,
    HV_SYS_REG_DBGBVR8_EL1,
    HV_SYS_REG_DBGBCR8_EL1,
    HV_SYS_REG_DBGWVR8_EL1,
    HV_SYS_REG_DBGWCR8_EL1,
    HV_SYS_REG_DBGBVR9_EL1,
    HV_SYS_REG_DBGBCR9_EL1,
    HV_SYS_REG_DBGWVR9_EL1,
    HV_SYS_REG_DBGWCR9_EL1,
    HV_SYS_REG_DBGBVR10_EL1,
    HV_SYS_REG_DBGBCR10_EL1,
    HV_SYS_REG_DBGWVR10_EL1,
    HV_SYS_REG_DBGWCR10_EL1,
    HV_SYS_REG_DBGBVR11_EL1,
    HV_SYS_REG_DBGBCR11_EL1,
    HV_SYS_REG_DBGWVR11_EL1,
    HV_SYS_REG_DBGWCR11_EL1,
    HV_SYS_REG_DBGBVR12_EL1,
    HV_SYS_REG_DBGBCR12_EL1,
    HV_SYS_REG_DBGWVR12_EL1,
    HV_SYS_REG_DBGWCR12_EL1,
    HV_SYS_REG_DBGBVR13_EL1,
    HV_SYS_REG_DBGBCR13_EL1,
    HV_SYS_REG_DBGWVR13_EL1,
    HV_SYS_REG_DBGWCR13_EL1,
    HV_SYS_REG_DBGBVR14_EL1,
    HV_SYS_REG_DBGBCR14_EL1,
    HV_SYS_REG_DBGWVR14_EL1,
    HV_SYS_REG_DBGWCR14_EL1,
    HV_SYS_REG_DBGBVR15_EL1,
    HV_SYS_REG_DBGBCR15_EL1,
    HV_SYS_REG_DBGWVR15_EL1,
    HV_SYS_REG_DBGWCR15_EL1,
    HV_SYS_REG_MPIDR_EL1,
    HV_SYS_REG_SCTLR_EL1,
    HV_SYS_REG_ACTLR_EL1,
    HV_SYS_REG_CPACR_EL1,
    HV_SYS_REG_TTBR0_EL1,
    HV_SYS_REG_TTBR1_EL1,
    HV_SYS_REG_TCR_EL1,
    HV_SYS_REG_APIAKEYLO_EL1,
    HV_SYS_REG_APIAKEYHI_EL1,
    HV_SYS_REG_APIBKEYLO_EL1,
    HV_SYS_REG_APIBKEYHI_EL1,
    HV_SYS_REG_APDAKEYLO_EL1,
    HV_SYS_REG_APDAKEYHI_EL1,
    HV_SYS_REG_APDBKEYLO_EL1,
    HV_SYS_REG_APDBKEYHI_EL1,
    HV_SYS_REG_APGAKEYLO_EL1,
    HV_SYS_REG_APGAKEYHI_EL1,
    HV_SYS_REG_SPSR_EL1,
    HV_SYS_REG_ELR_EL1,
    HV_SYS_REG_SP_EL0,
    HV_SYS_REG_AFSR0_EL1,
    HV_SYS_REG_AFSR1_EL1,
    HV_SYS_REG_ESR_EL1,
    HV_SYS_REG_FAR_EL1,
    HV_SYS_REG_PAR_EL1,
    HV_SYS_REG_MAIR_EL1,
    HV_SYS_REG_AMAIR_EL1,
    HV_SYS_REG_VBAR_EL1,
    HV_SYS_REG_CONTEXTIDR_EL1,
    HV_SYS_REG_TPIDR_EL1,
    HV_SYS_REG_CNTKCTL_EL1,
    HV_SYS_REG_CSSELR_EL1,
    HV_SYS_REG_TPIDR_EL0,
    HV_SYS_REG_TPIDRRO_EL0,
    HV_SYS_REG_CNTV_CTL_EL0,
    HV_SYS_REG_CNTV_CVAL_EL0,
    HV_SYS_REG_SP_EL1,
    HV_SYS_REG_CNTP_CTL_EL0,
    HV_SYS_REG_CNTP_CVAL_EL0,
};
static const hv_gic_icc_reg_t snapshot_icc[]={
    HV_GIC_ICC_REG_SRE_EL1,HV_GIC_ICC_REG_CTLR_EL1,HV_GIC_ICC_REG_PMR_EL1,
    HV_GIC_ICC_REG_BPR0_EL1,HV_GIC_ICC_REG_BPR1_EL1,
    HV_GIC_ICC_REG_AP0R0_EL1,HV_GIC_ICC_REG_AP1R0_EL1,
    HV_GIC_ICC_REG_IGRPEN0_EL1,HV_GIC_ICC_REG_IGRPEN1_EL1
};

struct snapshot_sme {uint8_t supported, streaming, za;uint16_t width;};
static struct snapshot_sme snapshot_sme_header(hv_vcpu_t cpu,struct snapshot_io *s){
    hv_vcpu_sme_state_t state={0};struct snapshot_sme saved={0};
    if(!s->restore){
        hv_return_t result=hv_vcpu_get_sme_state(cpu,&state);
        if(result!=HV_SUCCESS && result!=HV_UNSUPPORTED)s->error=1;
        saved.supported=result==HV_SUCCESS;saved.streaming=state.streaming_sve_mode_enabled;saved.za=state.za_storage_enabled;
        if(saved.streaming || saved.za){
            uint8_t data[65536];
            for(unsigned width=16;width<=256;width*=2){
                hv_return_t r=saved.streaming?hv_vcpu_get_sme_z_reg(cpu,HV_SME_Z_REG_0,data,width):hv_vcpu_get_sme_za_reg(cpu,data,width*width);
                if(r==HV_SUCCESS){saved.width=width;break;}
            }
            if(!saved.width)s->error=1;
        }
    }
    SNAP(s,saved.supported);SNAP(s,saved.streaming);SNAP(s,saved.za);SNAP(s,saved.width);
    if(saved.supported>1||saved.streaming>1||saved.za>1||
       ((!saved.supported)&&(saved.streaming||saved.za))||
       ((saved.streaming||saved.za)?(saved.width<16||saved.width>256||(saved.width&(saved.width-1))):saved.width!=0))s->error=1;
    if(s->restore && saved.supported && !s->error){
        state.streaming_sve_mode_enabled=saved.streaming;state.za_storage_enabled=saved.za;
        if(hv_vcpu_set_sme_state(cpu,&state))s->error=1;
    }
    return saved;
}
static void snapshot_sme_data(hv_vcpu_t cpu,struct snapshot_io *s,struct snapshot_sme saved){
    if(s->error)return;
    uint8_t data[65536]={0};
    if(saved.streaming){
        for(unsigned i=0;i<32;i++){
            if(!s->restore&&hv_vcpu_get_sme_z_reg(cpu,(hv_sme_z_reg_t)i,data,saved.width))s->error=1;
            snapshot_bytes(s,data,saved.width);
            if(s->restore&&!s->error&&hv_vcpu_set_sme_z_reg(cpu,(hv_sme_z_reg_t)i,data,saved.width))s->error=1;
        }
        for(unsigned i=0;i<16;i++){
            if(!s->restore&&hv_vcpu_get_sme_p_reg(cpu,(hv_sme_p_reg_t)i,data,saved.width/8))s->error=1;
            snapshot_bytes(s,data,saved.width/8);
            if(s->restore&&!s->error&&hv_vcpu_set_sme_p_reg(cpu,(hv_sme_p_reg_t)i,data,saved.width/8))s->error=1;
        }
    }
    if(saved.za){
        size_t size=(size_t)saved.width*saved.width;
        if(!s->restore&&hv_vcpu_get_sme_za_reg(cpu,data,size))s->error=1;
        snapshot_bytes(s,data,size);
        if(s->restore&&!s->error&&hv_vcpu_set_sme_za_reg(cpu,data,size))s->error=1;
        hv_sme_zt0_uchar64_t zt={0};uint8_t present=0;
        if(!s->restore)present=hv_vcpu_get_sme_zt0_reg(cpu,&zt)==HV_SUCCESS;
        SNAP(s,present);if(present>1)s->error=1;
        if(present){snapshot_bytes(s,&zt,64);if(s->restore&&!s->error&&hv_vcpu_set_sme_zt0_reg(cpu,&zt))s->error=1;}
    }
}

#endif
