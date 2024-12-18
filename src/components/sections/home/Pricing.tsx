import React from 'react';
import { Check } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { SectionHeader } from '@/components/ui/SectionHeader';

const PricingTier = ({ 
  name, 
  price, 
  description, 
  features, 
  buttonText, 
  isPopular 
}: {
  name: string;
  price: string;
  description: string;
  features: string[];
  buttonText: string;
  isPopular?: boolean;
}) => (
  <div className={`relative rounded-2xl p-8 h-full flex flex-col ${
    isPopular 
      ? 'bg-white border-2 border-blue-200 shadow-[0_0_50px_rgba(59,130,246,0.1)]' 
      : 'bg-white border border-gray-100'
  }`}>
    {isPopular && (
      <div className="absolute -top-4 left-1/2 -translate-x-1/2">
        <div className="bg-blue-600 text-white px-4 py-1 rounded-full text-sm font-medium">
          Most Popular
        </div>
      </div>
    )}
    <div className="mb-6">
      <h3 className="text-2xl font-bold text-gray-900 mb-2">{name}</h3>
      <p className="text-gray-600 mb-4">{description}</p>
      <div className="flex items-baseline gap-1">
        <span className="text-4xl font-bold text-gray-900">{price}</span>
        {price !== 'Custom' && <span className="text-gray-600">/month</span>}
      </div>
    </div>

    <div className="space-y-4 flex-grow">
      {features.map((feature, index) => (
        <div key={index} className="flex items-center gap-3">
          <Check className="w-5 h-5 text-blue-600 flex-shrink-0" />
          <span className="text-gray-600">{feature}</span>
        </div>
      ))}
    </div>

    <div className="mt-8">
      <Button 
        variant={isPopular ? 'primary' : 'outline'} 
        className="w-full"
      >
        {buttonText}
      </Button>
    </div>
  </div>
);

const Pricing = () => {
  const plans = [
    {
      name: 'Starter',
      price: '$29',
      description: 'Perfect for small businesses getting started with review management',
      buttonText: 'Get Started',
      features: [
        'Up to 20 reviews/month',
        'Review monitoring',
        'Basic reporting',
        'Email support'
      ]
    },
    {
      name: 'Professional',
      price: '$79',
      description: 'Ideal for growing businesses that need more advanced features',
      buttonText: 'Get Started',
      isPopular: true,
      features: [
        'Up to 100 reviews/month',
        'Review monitoring & alerts',
        'Priority support',
        'Custom reporting'
      ]
    },
    {
      name: 'Enterprise',
      price: '$125',
      description: 'For large organizations with custom requirements',
      buttonText: 'Contact Sales',
      features: [
        'Up to 250 reviews/month',
        '24/7 dedicated support',
        'Advanced monitoring',
        'Custom reporting'
      ]
    }
  ];

  return (
    <section id="pricing" className="py-12 bg-gradient-to-b from-blue-50 to-white">
      <div className="container mx-auto px-4">
        <SectionHeader
          title="Simple, Transparent Pricing"
          description="Choose the perfect plan for your business"
        />

        <div className="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">
          {plans.map((plan, index) => (
            <PricingTier key={index} {...plan} />
          ))}
        </div>
      </div>
    </section>
  );
};

export default Pricing;