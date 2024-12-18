import React from 'react';
import { X } from 'lucide-react';

interface Plan {
  id: number;
  name: string;
}

interface PlansPopupProps {
  plans: Plan[];
  onClose: () => void;
}

export const PlansPopup: React.FC<PlansPopupProps> = ({ plans, onClose }) => {
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 w-full max-w-md relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-gray-400 hover:text-gray-600 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>
        
        <h2 className="text-2xl font-bold mb-4">Available Plans</h2>
        
        <div className="space-y-2">
          {plans.map((plan) => (
            <div
              key={plan.id}
              className="p-4 border border-gray-100 rounded-lg hover:border-blue-100 transition-colors"
            >
              <p className="text-lg font-medium text-gray-900">{plan.name}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};