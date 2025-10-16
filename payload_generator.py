import random
import pandas as pd
from config import NORMAL_PAYLOADS, INJECTION_PAYLOADS

class PayloadGenerator:
    def __init__(self):
        self.normal_payloads = NORMAL_PAYLOADS
        self.injection_payloads = INJECTION_PAYLOADS
    
    def get_normal_payload(self, input_type='text'):
        """Get a random normal payload based on input type"""
        if input_type in self.normal_payloads:
            return random.choice(self.normal_payloads[input_type])
        return random.choice(self.normal_payloads['text'])
    
    def get_injection_payloads(self, payload_type='all'):
        """Get injection payloads of specified type"""
        if payload_type == 'all':
            all_payloads = []
            for payload_list in self.injection_payloads.values():
                all_payloads.extend(payload_list)
            return all_payloads
        elif payload_type in self.injection_payloads:
            return self.injection_payloads[payload_type]
        else:
            return []
    
    def generate_test_pairs(self, input_type='text', max_injections=3):
        """Generate pairs of normal and injection payloads for testing"""
        test_pairs = []
        
        # Add 2-3 normal payloads
        num_normal = random.randint(2, 3)
        for _ in range(num_normal):
            normal_payload = self.get_normal_payload(input_type)
            test_pairs.append(('safe', normal_payload))
        
        # Add injection payloads (sampled)
        injection_payloads = self.get_injection_payloads()
        num_injections = min(max_injections, len(injection_payloads))
        selected_injections = random.sample(injection_payloads, num_injections)
        
        for payload in selected_injections:
            test_pairs.append(('injection', payload))
        
        return test_pairs

    def create_sample_dataset(self):
        """Create a sample dataset if no existing dataset is found"""
        from config import SAMPLE_ENDPOINTS
        
        df = pd.DataFrame(SAMPLE_ENDPOINTS)
        return df